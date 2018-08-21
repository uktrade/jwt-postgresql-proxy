import asyncio
import collections
from functools import (
    partial,
)
import hashlib
import re
import secrets
import socket
import ssl
import struct

# Architected by nested processors, akin to middlewares in a typical HTTP
# server. They are added, "outermost" first, and can process the response
# of "inner" processors.
#
# However, they are different in that they can send data...
#
# - to an inner processor destined for the client
# - to an inner processor destined for the server
# - to an outer processor destined for the client
# - to an outer processor destined for the server
# - multiple messages, not just the one response to a request
# - to either client or server at any time, or choose _not_ to if 
#   conditions haven't been met, such as authentication
Processor = collections.namedtuple("Processor", (
    "c2s_from_outside", "c2s_from_inside", "s2c_from_outside", "s2c_from_inside"))

# How much we read at once. Messages _can_ be larger than this
# Often good to test this set to something really low to make
# sure the logic works for network reads that return only partial
# messages
MAX_READ = 16384

# Startup message (also called startup packets) don't have a type specified
START_MESSAGE_TYPE_LENGTH = 0
LATER_MESSAGE_TYPE_LENGTH = 1

# The length of messages itself takes 4 bytes
PAYLOAD_LENGTH_LENGTH = 4
PAYLOAD_LENGTH_FORMAT = "!L"

SSL_REQUEST_MESSAGE = B"\x00\x00\x00\x08\x04\xd2\x16/"
SSL_REQUEST_RESPONSE = B"S"

# Message tuples are constructed so their components can be concatanated together
# to return the bytes of the message suitable for transmission to Postgres
Message = collections.namedtuple("Message", (
    "type", "payload_length", "payload"))


def postgres_root_processor(loop, non_ssl_client_sock, server_sock, to_c2s_inner, to_s2c_inner,
                            **_):
    allow_data_to_next_processor = False
    possible_ssl_request = b""

    ssl_client_sock = None

    async def init_client_tls():
        nonlocal ssl_client_sock

        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        sslctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
        ssl_client_sock = sslctx.wrap_socket(
            non_ssl_client_sock,
            server_side=True,
            do_handshake_on_connect=False)
        ssl_client_sock.setblocking(False)

        while True:
            try:
                ssl_client_sock.do_handshake()
                break
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                # We could have something more efficient, e.g. doing things
                # with the asyncio readers, but it works
                await asyncio.sleep(0)

    def get_client_sock():
        return ssl_client_sock if ssl_client_sock else non_ssl_client_sock

    async def c2s_from_outside(data):
        nonlocal allow_data_to_next_processor
        nonlocal possible_ssl_request

        num_remaining = len(SSL_REQUEST_MESSAGE) - len(possible_ssl_request)
        possible_ssl_request, non_ssl_request = \
            possible_ssl_request + data[0:num_remaining], data[num_remaining:]

        if allow_data_to_next_processor:
            await to_c2s_inner(non_ssl_request)
        elif num_remaining and possible_ssl_request == SSL_REQUEST_MESSAGE:
            print(f'[client->proxy] {SSL_REQUEST_MESSAGE}')
            print(f'[proxy->client] {SSL_REQUEST_RESPONSE}')
            allow_data_to_next_processor = True
            await s2c_from_inside(SSL_REQUEST_RESPONSE)
            await init_client_tls()
        elif num_remaining and len(possible_ssl_request) == len(SSL_REQUEST_MESSAGE):
            close_all_connections()

    async def c2s_from_inside(data):
        await loop.sock_sendall(server_sock, data)

    async def s2c_from_outside(data):
        await to_s2c_inner(data)

    async def s2c_from_inside(data):
        await loop.sock_sendall(get_client_sock(), data)

    def on_read_available(sock, on_data):
        loop.create_task(_on_read_available(sock, on_data))

    async def _on_read_available(get_sock, on_data):
        # Unfortunately, when using SSL, this gets called repeatedly
        # even if there isn't any data
        try:
            while True:
                data = await loop.sock_recv(get_sock(), MAX_READ)
                if data:
                    await on_data(data)
                else:
                    break
        except ssl.SSLWantReadError:
            pass
        except BaseException:
            close_all_connections()

    # The SSL and non-TLS sockets share the same fileno, so we only
    # have to add the reader for one, and it still works after TLS upgrade
    loop.add_reader(non_ssl_client_sock.fileno(),
                    partial(on_read_available, get_client_sock, c2s_from_outside))
    loop.add_reader(server_sock.fileno(),
                    partial(on_read_available, lambda: server_sock, s2c_from_outside))

    def close_all_connections():
        if ssl_client_sock:
            ssl_client_sock.close()
        non_ssl_client_sock.close()
        server_sock.close()

    return Processor(c2s_from_outside, c2s_from_inside, s2c_from_outside, s2c_from_inside)

def postgres_message_parser(num_startup_messages):
    data_buffer = bytearray()
    messages_popped = 0

    def push_data(incoming_data):
        data_buffer.extend(incoming_data)

    def attempt_pop_message(type_length):
        """ Returns the next, possibly partly-received, message in data_buffer

        If the message is complete, then it's removed from the data buffer, and
        the return tuple's first component is True.
        """
        type_slice = slice(0, type_length)
        type_bytes = data_buffer[type_slice]
        has_type_bytes = len(type_bytes) == type_length

        payload_length_slice = slice(type_length, type_length + PAYLOAD_LENGTH_LENGTH)
        payload_length_bytes = data_buffer[payload_length_slice]
        has_payload_length_bytes = (
            has_type_bytes and len(payload_length_bytes) == PAYLOAD_LENGTH_LENGTH
        )

        # The protocol specifies that the message length specified _includes_ MESSAGE_LENGTH_LENGTH,
        # so we subtract to get the actual length of the message.
        payload_length = \
            unpack_length(payload_length_bytes) if has_payload_length_bytes else \
            0

        payload_slice = slice(
            type_length + PAYLOAD_LENGTH_LENGTH,
            type_length + PAYLOAD_LENGTH_LENGTH + payload_length,
        )
        payload_bytes = data_buffer[payload_slice]
        has_payload_bytes = has_payload_length_bytes and len(payload_bytes) == payload_length
        message_length = type_length + PAYLOAD_LENGTH_LENGTH + payload_length

        to_remove = \
            slice(0, message_length) if has_payload_bytes else \
            slice(0, 0)

        data_buffer[to_remove] = bytearray()

        return (
            has_payload_bytes,
            Message(bytes(type_bytes), bytes(payload_length_bytes), bytes(payload_bytes)),
        )

    def extract_messages(data):
        """ Returns a list of Messages, each Message being the raw bytes of
        components of Postgres messages passed in data, or combined with that of
        previous calls where the data passed ended with an incomplete message
        """
        push_data(data)

        nonlocal messages_popped

        messages = []
        while True:
            pop_startup_message = messages_popped < num_startup_messages

            type_length = \
                START_MESSAGE_TYPE_LENGTH if pop_startup_message else \
                LATER_MESSAGE_TYPE_LENGTH
            has_popped, message = attempt_pop_message(type_length)

            if not has_popped:
                break

            messages_popped += 1
            messages.append(message)

        return messages

    return extract_messages


def postgres_parser_processor(to_c2s_outer, to_c2s_inner, to_s2c_outer, to_s2c_inner):
    c2s_parser = postgres_message_parser(num_startup_messages=1)
    s2c_parser = postgres_message_parser(num_startup_messages=0)

    async def c2s_from_outside(data):
        messages = c2s_parser(data)
        await to_c2s_inner(messages)

    async def c2s_from_inside(messages):
        await to_c2s_outer(b"".join(flatten(messages)))

    async def s2c_from_outside(data):
        messages = s2c_parser(data)
        await to_s2c_inner(messages)

    async def s2c_from_inside(messages):
        await to_s2c_outer(b"".join(flatten(messages)))

    return Processor(c2s_from_outside, c2s_from_inside, s2c_from_outside, s2c_from_inside)


def postgres_log_processor(to_c2s_outer, to_c2s_inner, to_s2c_outer, to_s2c_inner):

    def log_all_messages(logging_title, messages):
        for message in messages:
            print(f"[{logging_title}] " + str(message))

    async def c2s_from_outside(messages):
        log_all_messages('client->proxy', messages)
        await to_c2s_inner(messages)

    async def c2s_from_inside(messages):
        log_all_messages('proxy->server', messages)
        await to_c2s_outer(messages)

    async def s2c_from_outside(messages):
        log_all_messages('server->proxy', messages)
        await to_s2c_inner(messages)

    async def s2c_from_inside(messages):
        log_all_messages('proxy->client', messages)
        await to_s2c_outer(messages)

    return Processor(c2s_from_outside, c2s_from_inside, s2c_from_outside, s2c_from_inside)


def postgres_auth_processor(to_c2s_outer, to_c2s_inner, to_s2c_outer, to_s2c_inner):
    # Experimental replacement of the username & password
    correct_client_password = b"proxy_mysecret"
    correct_server_password = b"mysecret"

    correct_client_username = b"proxy_postgres"

    # This could be returned back to the client, so it should _not_ be treated as secret
    correct_server_username = b"postgres"

    server_salt = None
    client_salt = None

    def to_server_startup(message):
        # The startup message seems to have an extra null character at the beginning,
        # which the documentation doesn't suggest

        pairs_list = re.compile(b"\x00([^\x00]+)\x00([^\x00]*)").findall(message.payload)
        pairs = dict(pairs_list)
        incorrect_user = md5(secrets.token_bytes(32))
        client_username = pairs[b'user']
        server_username = \
            correct_server_username if client_username == correct_client_username else \
            incorrect_user

        pairs_to_send = {**pairs, b'user': server_username}
        new_payload = b"\x00" + b"".join(flatten(
            (key, b"\x00", pairs_to_send[key], b"\x00")
            for key, _ in pairs_list
        )) + b"\x00"
        new_payload_length_bytes = pack_length(len(new_payload))

        return message._replace(payload_length=new_payload_length_bytes, payload=new_payload)

    def to_server_md5_response(message):
        client_md5 = message.payload[3:-1]
        correct_client_md5 = md5_salted(
            correct_client_password, correct_client_username, client_salt,
        )
        correct_server_md5 = md5_salted(
            correct_server_password, correct_server_username, server_salt,
        )
        md5_incorrect = md5(secrets.token_bytes(32))
        server_md5 = \
            correct_server_md5 if client_md5 == correct_client_md5 else \
            md5_incorrect
        return message._replace(payload=b"md5" + server_md5 + b"\x00")

    async def c2s_from_outside(messages):
        await to_c2s_inner([
            to_server_startup(message) if is_startup else \
            to_server_md5_response(message) if is_md5_response else \
            message
            for message in messages
            for is_startup in (message.type == b"",)
            for is_md5_response in (message.type == b"p" and message.payload[0:3] == b"md5",)
        ])

    async def c2s_from_inside(messages):
        await to_c2s_outer(messages)

    def to_client_md5_request(message):
        return message._replace(payload=message.payload[0:4] + client_salt)

    async def s2c_from_outside(messages):
        nonlocal server_salt
        nonlocal client_salt

        for message in messages:
            is_md5_request = message.type == b"R" and message.payload[0:4] == b"\x00\x00\x00\x05"
            server_salt, client_salt = \
                (message.payload[4:8], secrets.token_bytes(4)) if is_md5_request else \
                (server_salt, client_salt)
            message_to_yield = \
                to_client_md5_request(message) if is_md5_request else \
                message
            await to_s2c_inner([message_to_yield])

    async def s2c_from_inside(messages):
        await to_s2c_outer(messages)

    return Processor(c2s_from_outside, c2s_from_inside, s2c_from_outside, s2c_from_inside)


def echo_processor(to_c2s_outer, to_s2c_outer, **_):
    ''' Processor to not have to special case the innermost processor '''

    async def c2s_from_outside(data):
        await to_c2s_outer(data)

    async def c2s_from_inside(_):
        pass

    async def s2c_from_outside(data):
        await to_s2c_outer(data)

    async def s2c_from_inside(_):
        pass

    return Processor(c2s_from_outside, c2s_from_inside, s2c_from_outside, s2c_from_inside)


async def handle_client(loop, client_sock):
    server_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM,
                                proto=socket.IPPROTO_TCP)
    server_sock.setblocking(False)
    await loop.sock_connect(server_sock, ("127.0.0.1", 5432))

    async def to_c2s_inner(i, data):
        return await processors[i + 1].c2s_from_outside(data)

    async def to_c2s_outer(i, data):
        return await processors[i - 1].c2s_from_inside(data)

    async def to_s2c_inner(i, data):
        return await processors[i + 1].s2c_from_outside(data)

    async def to_s2c_outer(i, data):
        return await processors[i - 1].s2c_from_inside(data)

    outermost_processor_constructor = partial(
        postgres_root_processor,
        loop, client_sock, server_sock,
    )

    processors = [
        processor_constructor(
            to_c2s_outer=partial(to_c2s_outer, i),
            to_c2s_inner=partial(to_c2s_inner, i),
            to_s2c_outer=partial(to_s2c_outer, i),
            to_s2c_inner=partial(to_s2c_inner, i),
        )
        for i, processor_constructor in enumerate([
            outermost_processor_constructor,
            postgres_parser_processor,
            postgres_log_processor,
            postgres_auth_processor,
            echo_processor,
        ])
    ]


def unpack_length(length_bytes):
    return struct.unpack(PAYLOAD_LENGTH_FORMAT, length_bytes)[0] - PAYLOAD_LENGTH_LENGTH


def pack_length(length):
    return struct.pack(PAYLOAD_LENGTH_FORMAT, length + PAYLOAD_LENGTH_LENGTH)


def md5(data):
    return hashlib.md5(data).hexdigest().encode("utf-8")


def md5_salted(password, username, salt):
    return md5(md5(password + username) + salt)


def flatten(list_to_flatten):
    return (item for sublist in list_to_flatten for item in sublist)


async def async_main(loop):
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    sock.setblocking(False)
    sock.bind(("", 7777))
    sock.listen(socket.IPPROTO_TCP)

    while True:
        client_sock, _ = await loop.sock_accept(sock)
        # Unsure if this is needed
        client_sock.setblocking(False)
        await handle_client(loop, client_sock)


def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_main(loop))
    loop.run_forever()


if __name__ == "__main__":
    main()
