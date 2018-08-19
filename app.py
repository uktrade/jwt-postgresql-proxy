import asyncio
import collections
import hashlib
import secrets
import struct

# How much we read at once. Messages _can_ be larger than this
MAX_READ = 16384

# Startup message (also called startup packets) don't have a type specified
START_MESSAGE_TYPE_LENGTH = 0
LATER_MESSAGE_TYPE_LENGTH = 1

# The length of messages itself takes 4 bytes
PAYLOAD_LENGTH_LENGTH = 4
PAYLOAD_LENGTH_FORMAT = "!L"

NO_DATA_TYPE = b"N"

Message = collections.namedtuple("Message", ("type", "payload_length", "payload"))


def postgres_message_parser(num_startup_messages):
    data_buffer = bytearray()
    messages_popped = 0

    def push_data(incoming_data):
        data_buffer.extend(incoming_data)

    def unpack_length(length_bytes):
        return struct.unpack(PAYLOAD_LENGTH_FORMAT, length_bytes)[0]

    def attempt_pop_message(type_length):
        """ Returns the next, possibly partly-received, message in data_buffer

        If the message is complete, then it's removed from the data buffer, and
        the return tuple's first component is True.
        """
        type_slice = slice(0, type_length)
        type_bytes = data_buffer[type_slice]
        has_type_bytes = len(type_bytes) == type_length

        # The documentation is a bit wrong: the 'N' type for no data, is _not_ followed
        # by a length
        payload_length_length = \
            0 if has_type_bytes and type_bytes == NO_DATA_TYPE else \
            PAYLOAD_LENGTH_LENGTH

        payload_length_slice = slice(type_length, type_length + payload_length_length)
        payload_length_bytes = data_buffer[payload_length_slice]
        has_payload_length_bytes = (
            has_type_bytes and len(payload_length_bytes) == payload_length_length
        )

        # The protocol specifies that the message length specified _includes_ MESSAGE_LENGTH_LENGTH,
        # so we subtract to get the actual length of the message.
        should_unpack = has_payload_length_bytes and payload_length_length
        payload_length = \
            unpack_length(payload_length_bytes) - payload_length_length if should_unpack else \
            0

        payload_slice = slice(
            type_length + payload_length_length,
            type_length + payload_length_length + payload_length,
        )
        payload_bytes = data_buffer[payload_slice]
        has_payload_bytes = has_payload_length_bytes and len(payload_bytes) == payload_length
        message_length = type_length + payload_length_length + payload_length

        to_remove = \
            slice(0, message_length) if has_payload_bytes else \
            slice(0, 0)

        data_buffer[to_remove] = bytearray()

        return (
            has_payload_bytes,
            Message(bytes(type_bytes), bytes(payload_length_bytes), bytes(payload_bytes)),
        )

    def extract_messages(data):
        """ Yields a generator of Messages, each Message being the raw bytes of
        components of Postgres messages passed in data, or combined with that of
        previous calls where the data passed ended with an incomplete message

        The components of the triple:

          type of the message,
          the length of the payload,
          the payload itself,

        Each component is optional, and will be the empty byte if its not present
        Each Message is so constructed so that full original bytes can be retrieved
        by just concatanating them together, to make proxying easier
        """
        push_data(data)

        nonlocal messages_popped

        while True:
            pop_startup_message = messages_popped < num_startup_messages

            type_length = \
                START_MESSAGE_TYPE_LENGTH if pop_startup_message else \
                LATER_MESSAGE_TYPE_LENGTH
            has_popped, message = attempt_pop_message(type_length)

            if not has_popped:
                break

            messages_popped += 1
            yield message

    return extract_messages


def postgres_auth_interceptor():
    # Experimental replacement of the password
    correct_client_password = b"proxy_mysecret"
    correct_server_password = b"mysecret"

    # This would have to be read from the messages?
    username = b"postgres"

    server_salt = None
    client_salt = None

    def log_message(logging_title, message):
        print(f"[{logging_title}] " + str(message))

    def to_server_md5_response(message):
        client_md5 = message.payload[3:-1]
        correct_client_md5 = md5_salted(correct_client_password, username, client_salt)
        correct_server_md5 = md5_salted(correct_server_password, username, server_salt)
        md5_incorrect = md5(secrets.token_bytes(32))
        server_md5 = \
            correct_server_md5 if client_md5 == correct_client_md5 else \
            md5_incorrect
        return message._replace(payload=b"md5" + server_md5 + b"\x00")

    def client_to_server(messages):
        for message in messages:
            log_message("client->proxy", message)
            is_md5_response = message.type == b"p" and message.payload[0:3] == b"md5"
            message_to_yield = \
                to_server_md5_response(message) if is_md5_response else \
                message
            log_message("proxy->server", message_to_yield)
            yield message_to_yield

    def to_client_md5_request(message):
        return message._replace(payload=message.payload[0:4] + client_salt)

    def server_to_client(messages):
        nonlocal server_salt
        nonlocal client_salt

        for message in messages:
            log_message("server->proxy", message)
            is_md5_request = message.type == b"R" and message.payload[0:4] == b"\x00\x00\x00\x05"
            server_salt, client_salt = \
                (message.payload[4:8], secrets.token_bytes(4)) if is_md5_request else \
                (server_salt, client_salt)
            message_to_yield = \
                to_client_md5_request(message) if is_md5_request else \
                message
            log_message("proxy->client", message_to_yield)
            yield message_to_yield

    return client_to_server, server_to_client


async def handle_client(client_reader, client_writer):
    try:
        server_reader, server_writer = await asyncio.open_connection("127.0.0.1", 5432)

        client_to_server_interceptor, server_to_client_interceptor = postgres_auth_interceptor()

        await asyncio.gather(
            # The documentation suggests there is one startup packets sent from
            # the client, but there are actually two
            pipe_intercepted(
                client_reader, server_writer, client_to_server_interceptor, num_startup_messages=2
            ),
            pipe_intercepted(
                server_reader, client_writer, server_to_client_interceptor, num_startup_messages=0
            ),
        )
    finally:
        client_writer.close()
        server_writer.close()


async def pipe_intercepted(reader, writer, interceptor, num_startup_messages):
    message_parser = postgres_message_parser(num_startup_messages)
    while not reader.at_eof():
        data = await reader.read(MAX_READ)
        messages = message_parser(data)
        intercepted_messages = interceptor(messages)
        writer.write(b"".join(flatten(intercepted_messages)))


def md5(data):
    return hashlib.md5(data).hexdigest().encode("utf-8")


def md5_salted(password, username, salt):
    return md5(md5(password + username) + salt)


def flatten(list_to_flatten):
    return (item for sublist in list_to_flatten for item in sublist)


async def async_main():
    await asyncio.start_server(handle_client, "0.0.0.0", 7777)


def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_main())
    loop.run_forever()


if __name__ == "__main__":
    main()
