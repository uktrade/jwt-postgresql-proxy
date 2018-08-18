import asyncio
import struct

# How much we read at once. Messages _can_ be larger than this
MAX_READ = 16384

# Startup message (also called startup packets) don't have a type specified
START_MESSAGE_TYPE_LENGTH = 0
LATER_MESSAGE_TYPE_LENGTH = 1

# The length of messages itself takes 4 bytes
MESSAGE_LENGTH_LENGTH = 4
MESSAGE_LENGTH_FORMAT = '!L'

NO_DATA_TYPE = b'N'


def postgres_message_reader(startup_messages):
    remaining = bytearray()
    messages_popped = 0

    def attempt_pop_message(message_type_length):
        message_type_slice = slice(0, message_type_length)
        message_type_bytes = remaining[message_type_slice]
        has_message_type_bytes = len(message_type_bytes) == message_type_length

        # The documentation is a bit wrong: the 'N' message type for no data, is _not_ followed
        # by a length
        message_length_length = \
            0 if has_message_type_bytes and message_type_bytes == NO_DATA_TYPE else \
            MESSAGE_LENGTH_LENGTH

        message_length_slice = slice(message_type_length, message_type_length + message_length_length)
        message_length_bytes = remaining[message_length_slice]
        has_message_length_bytes = has_message_type_bytes and len(message_length_bytes) == message_length_length

        # The protocol specifies that the message length specified _includes_ MESSAGE_LENGTH_LENGTH,
        # so we subtract to get the actual length of the message.
        message_length = \
            (struct.unpack(MESSAGE_LENGTH_FORMAT, message_length_bytes)[0] - MESSAGE_LENGTH_LENGTH) if has_message_length_bytes and message_length_bytes else \
            0

        message_slice = slice(message_type_length + MESSAGE_LENGTH_LENGTH, message_type_length + MESSAGE_LENGTH_LENGTH + message_length)
        message_bytes = remaining[message_slice]
        has_message_bytes = has_message_length_bytes and len(message_bytes) == message_length

        to_remove = \
            slice(0, message_type_length + MESSAGE_LENGTH_LENGTH + message_length) if has_message_bytes else \
            slice(0, 0)

        remaining[to_remove] = bytearray()

        return has_message_bytes, message_type_bytes, message_length_bytes, message_bytes

    def get_messages(incoming_buf):
        nonlocal messages_popped
        remaining.extend(incoming_buf)

        messages = []
        while True:
            pop_startup_message = messages_popped < startup_messages

            has_popped, message_type_bytes, message_length_bytes, message_bytes = \
                attempt_pop_message(START_MESSAGE_TYPE_LENGTH) if pop_startup_message else \
                attempt_pop_message(LATER_MESSAGE_TYPE_LENGTH)

            if not has_popped:
                break

            messages_popped += 1
            messages.append([message_type_bytes, message_length_bytes, message_bytes])

        return messages

    async def _read(reader):
        # We only return messages that we have logged, to prevent an attacker from constructing
        # messages that somehow fail our own parsing, but would pass Postgres'
        data = await reader.read(MAX_READ)
        messages = get_messages(data)
        for message in messages:
            print(str(startup_messages) + ' -----------------')
            print(message)
        return b''.join(flatten(messages))

    return _read

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
            await asyncio.gather(
                # The documentation suggests there is one startup packets sent from
                # the client, but there are actually two
                pipe_logged(client_reader, server_writer, startup_messages=2),
                pipe_logged(server_reader, client_writer, startup_messages=0),
            )
        finally:
            client_writer.close()

    async def pipe_logged(reader, writer, startup_messages):
        message_reader = postgres_message_reader(startup_messages)

        try:
            while not reader.at_eof():
                writer.write(await message_reader(reader))
        finally:
            writer.close()

    server = await asyncio.start_server(handle_client, '0.0.0.0', 7777)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.run_forever()
