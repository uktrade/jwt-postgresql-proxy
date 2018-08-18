import asyncio
import struct

# How much we read at once. Messages _can_ be larger than this
MAX_READ = 16384

# Startup message (also called startup packets) don't have a type specified
START_MESSAGE_TYPE_LENGTH = 0
LATER_MESSAGE_TYPE_LENGTH = 1

# The length of messages itself takes 4 bytes
PAYLOAD_LENGTH_LENGTH = 4
PAYLOAD_LENGTH_FORMAT = '!L'

NO_DATA_TYPE = b'N'


def postgres_message_parser(num_startup_messages):
    data_buffer = bytearray()
    messages_popped = 0

    def push_data(incoming_data):
        data_buffer.extend(incoming_data)

    def attempt_pop_message(type_length):
        ''' Returns the next, possibly partly-received, message in data_buffer

        If the message is complete, then it's removed from the data buffer, and
        the return tuple's first component is True.
        '''
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
        has_payload_length_bytes = has_type_bytes and len(payload_length_bytes) == payload_length_length

        # The protocol specifies that the message length specified _includes_ MESSAGE_LENGTH_LENGTH,
        # so we subtract to get the actual length of the message.
        payload_length = \
            (struct.unpack(PAYLOAD_LENGTH_FORMAT, payload_length_bytes)[0] - payload_length_length) if has_payload_length_bytes and payload_length_length else \
            0

        payload_slice = slice(type_length + payload_length_length, type_length + payload_length_length + payload_length)
        payload_bytes = data_buffer[payload_slice]
        has_payload_bytes = has_payload_length_bytes and len(payload_bytes) == payload_length

        to_remove = \
            slice(0, type_length + PAYLOAD_LENGTH_LENGTH + payload_length) if has_payload_bytes else \
            slice(0, 0)

        data_buffer[to_remove] = bytearray()

        return has_payload_bytes, bytes(type_bytes), bytes(payload_length_bytes), bytes(payload_bytes)

    def extract_messages(data):
        ''' Returns a list of triples, each triple being the raw bytes of 
        components of Postgres messages passed in data, or combined with that of
        previous calls where the data passed ended with an incomplete message

        The components of the triple:

          type of the message,
          the length of the payload,
          the payload itself,

        Each component is optional, and will be the empty byte if its not present
        The triples are so constructed so that full original bytes can be retrieved
        by just concatanating them together, to make proxying easier
        '''
        push_data(data)

        nonlocal messages_popped

        while True:
            pop_startup_message = messages_popped < num_startup_messages

            has_popped, type_bytes, payload_length_bytes, payload_bytes = \
                attempt_pop_message(START_MESSAGE_TYPE_LENGTH) if pop_startup_message else \
                attempt_pop_message(LATER_MESSAGE_TYPE_LENGTH)

            if not has_popped:
                break

            messages_popped += 1
            yield [type_bytes, payload_length_bytes, payload_bytes]

    return extract_messages


def postgress_message_interceptor():
    ''' Keeps a track of the passed messages, in order to transform them.
    For example, to intercep password request/responses
    '''

    def log_messages(logging_title, messages):
        for message in messages:
            print(str(logging_title) + ' -----------------')
            print(message)
            yield message

    def client_to_server(messages):
        return log_messages('client', messages)

    def server_to_client(messages):
        return log_messages('server', messages)

    return client_to_server, server_to_client


def flatten(list_to_flatten):
    return (
        item
        for sublist in list_to_flatten
        for item in sublist
    )

async def main():
    async def handle_client(client_reader, client_writer):
        try:
            server_reader, server_writer = await asyncio.open_connection('127.0.0.1', 5432)

            client_to_server_interceptor, server_to_client_interceptor = postgress_message_interceptor()

            await asyncio.gather(
                # The documentation suggests there is one startup packets sent from
                # the client, but there are actually two
                pipe_intercepted(client_reader, server_writer, client_to_server_interceptor,
                                 num_startup_messages=2),
                pipe_intercepted(server_reader, client_writer, server_to_client_interceptor,
                                 num_startup_messages=0),
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
            writer.write(b''.join(flatten(intercepted_messages)))

    server = await asyncio.start_server(handle_client, '0.0.0.0', 7777)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.run_forever()
