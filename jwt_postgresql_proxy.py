import asyncio
import collections
import contextlib
from functools import (
    partial,
)
import re
import socket
import ssl
import struct



class ConnectionClosed(Exception):
    pass


class ProtocolError(Exception):
    pass


async def server():
    TLS_REQUEST = b'\x00\x00\x00\x08\x04\xd2\x16/'
    TLS_RESPONSE = b'S'
    STARTUP_MESSAGE_HEADER = struct.Struct('!LL')
    MESSAGE_HEADER = struct.Struct('!cL')
    INT = struct.Struct('!L')

    AUTHENTICATION_CLEARTEXT_PASSWORD = 3
    PASSWORD_RESPONSE = b'p'

    # How much to read from the socket at once
    MAX_READ = 66560

    # For messages that have to be in memory, how big they can be before we throw an error
    MAX_IN_MEMORY_MESSAGE_LENGTH = 66560

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    loop = asyncio.get_running_loop()
    socket_timeout = 10


    async def handle_client(client_sock):
        # Client must request TLS
        chunk = await recv(client_sock, len(TLS_REQUEST))
        if chunk != TLS_REQUEST:
            raise ProtocolError()
        await send_all(client_sock, TLS_RESPONSE)
        ssl_client_sock = ssl_context.wrap_socket(client_sock, server_side=True, do_handshake_on_connect=False)
        print('....')
        await tls_complete_handshake(ssl_client_sock)
        print('Done han')

        startup_message_len, startup_protocol = STARTUP_MESSAGE_HEADER.unpack(await recv_exactly(ssl_client_sock, STARTUP_MESSAGE_HEADER.size))
        if startup_message_len > MAX_IN_MEMORY_MESSAGE_LENGTH:
            raise ProtocolError('Startup message too large')

        startup_key_value_pairs = await recv_exactly(ssl_client_sock, startup_message_len - STARTUP_MESSAGE_HEADER.size)
        pairs = dict(re.compile(b"([^\x00]+)\x00([^\x00]*)").findall(startup_key_value_pairs))
        claimed_user = pairs[b'user']
        database = pairs[b'database']

        await send_all(ssl_client_sock, MESSAGE_HEADER.pack(b'R', 4 + INT.size) + INT.pack(AUTHENTICATION_CLEARTEXT_PASSWORD))

        # Password response
        tag, payload_length = MESSAGE_HEADER.unpack(await recv_exactly(ssl_client_sock, MESSAGE_HEADER.size))
        if payload_length > MAX_IN_MEMORY_MESSAGE_LENGTH:
            raise ProtocolError('Password response message too large')

        if tag != PASSWORD_RESPONSE:
            raise ProtocolError('Expected password to request for password')

        password = (await recv_exactly(ssl_client_sock, payload_length - 4))[:-1]
        print('password', password)
        # tag, length, message_body_iter = await get_message(ssl_client_sock)

        # tag, length, message_body_iter = await get_message(ssl_client_sock)
        # # The server requests password authentication
        # await send_message('R', length, [''])


    def get_new_socket():
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        return sock

    async def shutdown_socket(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
            while True:
                await recv(sock, recv_bufsize=128)
        except (OSError, ConnectionClosed):
            pass

    async def tls_complete_handshake(ssl_sock):
        try:
            return ssl_sock.do_handshake()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass

        def handshake():
            try:
                ssl_sock.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError) as exception:
                reset_timeout()
            except Exception as exception:
                loop.remove_reader(fileno)
                loop.remove_writer(fileno)
                if not done.done():
                    done.set_exception(exception)
            else:
                loop.remove_reader(fileno)
                loop.remove_writer(fileno)
                if not done.done():
                    done.set_result(None)

        done = asyncio.Future()
        fileno = ssl_sock.fileno()
        loop.add_reader(fileno, handshake)
        loop.add_writer(fileno, handshake)

        try:
            with timeout(socket_timeout) as reset_timeout:
                return await done
        finally:
            loop.remove_reader(fileno)
            loop.remove_writer(fileno)

    async def recv_exactly(sock, amount):
        chunks = []
        while amount:
            chunk = await recv(sock, min(amount, MAX_READ))
            print('got chunk eact', len(chunk), chunk)
            chunks.append(chunk)
            amount -= len(chunks[-1])
        return b''.join(chunks)

    async def recv(sock, recv_bufsize):
        incoming = await _recv(sock, recv_bufsize)
        if not incoming:
            raise ConnectionClosed()
        return incoming

    async def send_all(sock, data):
        try:
            latest_num_bytes = sock.send(data)
        except (BlockingIOError, ssl.SSLWantWriteError):
            latest_num_bytes = 0
        else:
            if latest_num_bytes == 0:
                raise ConnectionClosed()

        if latest_num_bytes == len(data):
            return

        total_num_bytes = latest_num_bytes

        def writer():
            nonlocal total_num_bytes
            try:
                latest_num_bytes = sock.send(data_memoryview[total_num_bytes:])
            except (BlockingIOError, ssl.SSLWantWriteError):
                pass
            except Exception as exception:
                loop.remove_writer(fileno)
                if not result.done():
                    result.set_exception(exception)
            else:
                total_num_bytes += latest_num_bytes
                if latest_num_bytes == 0 and not result.done():
                    loop.remove_writer(fileno)
                    result.set_exception(ConnectionClosed())
                elif total_num_bytes == len(data) and not result.done():
                    loop.remove_writer(fileno)
                    result.set_result(None)
                else:
                    reset_timeout()

        result = asyncio.Future()
        fileno = sock.fileno()
        loop.add_writer(fileno, writer)
        data_memoryview = memoryview(data)

        try:
            with timeout(socket_timeout) as reset_timeout:
                return await result
        finally:
            loop.remove_writer(fileno)


    async def _recv(sock, recv_bufsize):
        try:
            return sock.recv(recv_bufsize)
        except (BlockingIOError, ssl.SSLWantReadError):
            pass

        def reader():
            try:
                chunk = sock.recv(recv_bufsize)
            except (BlockingIOError, ssl.SSLWantReadError):
                pass
            except Exception as exception:
                loop.remove_reader(fileno)
                if not result.done():
                    result.set_exception(exception)
            else:
                loop.remove_reader(fileno)
                if not result.done():
                    result.set_result(chunk)

        result = asyncio.Future()
        fileno = sock.fileno()
        loop.add_reader(fileno, reader)

        try:
            with timeout(socket_timeout):
                return await result
        finally:
            loop.remove_reader(fileno)

    @contextlib.contextmanager
    def timeout(max_time):

        cancelling_due_to_timeout = False
        current_task = asyncio.current_task()

        def cancel():
            nonlocal cancelling_due_to_timeout
            cancelling_due_to_timeout = True
            current_task.cancel()

        def reset():
            nonlocal handle
            handle.cancel()
            handle = loop.call_later(max_time, cancel)

        handle = loop.call_later(max_time, cancel)

        try:
            yield reset
        except asyncio.CancelledError:
            if cancelling_due_to_timeout:
                raise asyncio.TimeoutError()
            raise
        finally:
            handle.cancel()

    async def _client_task(client_sock):
        try:
            await handle_client(client_sock)
        finally:
            await shutdown_socket(client_sock)
            client_sock.close()

    sock = get_new_socket()
    print(sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
    sock.bind(("127.0.0.1", 7777))
    sock.listen(socket.IPPROTO_TCP)

    try:
        while True:
            client_sock, _ = await loop.sock_accept(sock)
            client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            loop.create_task(_client_task(client_sock))
            client_sock = None  # To make sure we don't have it hanging around
    finally:
        print('shutting down', sock)
        sock.close()
        print('after', sock)


def main():
    asyncio.run(server())


if __name__ == "__main__":
    main()
