from gevent import monkey
monkey.patch_all()

from base64 import urlsafe_b64decode
import collections
import contextlib
from functools import (
    partial,
)
import re
import gevent
import json
import socket
import ssl
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

public_key = \
    b'-----BEGIN PUBLIC KEY-----\n' \
    b'MCowBQYDK2VwAyEAe9+zIz+CH9E++J0qiE6aS657qzxsNWIEf2BZcUAQF94=\n' \
    b'-----END PUBLIC KEY-----\n'
public_key = load_pem_public_key(public_key, backend=default_backend())


class ConnectionClosed(Exception):
    pass


class ProtocolError(Exception):
    pass


def server():
    TLS_REQUEST = b'\x00\x00\x00\x08\x04\xd2\x16/'
    TLS_RESPONSE = b'S'

    STARTUP_MESSAGE_HEADER = struct.Struct('!LL')
    MESSAGE_HEADER = struct.Struct('!cL')
    INT = struct.Struct('!L')

    AUTHENTICATION_CLEARTEXT_PASSWORD = 3
    AUTHENTICATION_OK = 0
    PASSWORD_RESPONSE = b'p'

    # How much to read from the socket at once
    MAX_READ = 66560

    # For messages that have to be in memory, how big they can be before we throw an error
    MAX_IN_MEMORY_MESSAGE_LENGTH = 66560

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ssl_context.load_cert_chain(certfile='server.crt', keyfile='server.key')

    def b64_decode(b64_bytes):
        return urlsafe_b64decode(b64_bytes + (b'=' * ((4 - len(b64_bytes) % 4) % 4)))

    def handle_client_pre_tls(client_sock):
        ssl_client_sock = None

        try:
            chunk = recv_exactly(client_sock, len(TLS_REQUEST))
            if chunk != TLS_REQUEST:
                client_sock.sendall(MESSAGE_HEADER.pack(b'E', 4 + 1) + b'\x00')
                raise ProtocolError()
            client_sock.sendall(TLS_RESPONSE)

            ssl_client_sock = ssl_context.wrap_socket(client_sock, server_side=True)

            handle_client_post_tls(ssl_client_sock)
        finally:
            if ssl_client_sock is not None:
                client_sock = ssl_client_sock.unwrap()
            try:
                client_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                # The client could have shut it down alread
                pass
            client_sock.close()

    def handle_client_post_tls(ssl_client_sock):
        startup_message_len, protocol_version = STARTUP_MESSAGE_HEADER.unpack(recv_exactly(ssl_client_sock, STARTUP_MESSAGE_HEADER.size))
        if startup_message_len > MAX_IN_MEMORY_MESSAGE_LENGTH:
            raise ProtocolError('Startup message too large')

        if protocol_version != 196608:
            ssl_client_sock.sendall(MESSAGE_HEADER.pack(b'E', 4 + 1) + b'\x00')
            return

        startup_key_value_pairs = recv_exactly(ssl_client_sock, startup_message_len - STARTUP_MESSAGE_HEADER.size)
        pairs = dict(re.compile(b"([^\x00]+)\x00([^\x00]*)").findall(startup_key_value_pairs))
        claimed_user = pairs[b'user']
        database = pairs[b'database']

        ssl_client_sock.sendall(MESSAGE_HEADER.pack(b'R', 4 + INT.size) + INT.pack(AUTHENTICATION_CLEARTEXT_PASSWORD))

        # Password response
        tag, payload_length = MESSAGE_HEADER.unpack(recv_exactly(ssl_client_sock, MESSAGE_HEADER.size))
        if payload_length > MAX_IN_MEMORY_MESSAGE_LENGTH:
            raise ProtocolError('Password response message too large')

        if tag != PASSWORD_RESPONSE:
            raise ProtocolError('Expected password to request for password')

        password = (recv_exactly(ssl_client_sock, payload_length - 4))[:-1]
        header_b64, payload_b64, signature_b64 = password.split(b'.')

        try:
            public_key.verify(b64_decode(signature_b64), header_b64 + b'.' + payload_b64)
        except InvalidSignature:
            is_valid = False
        else:
            is_valid = True

        if not is_valid:
            failed = \
                b'S' + b'FATAL\x00' + \
                b'M' + b'Signature verification failed\x00' + \
                b'C' + b'28P01\x00' + \
                b'\x00'
            ssl_client_sock.sendall(MESSAGE_HEADER.pack(b'E', 4 + len(failed)) + failed)
            return

        ssl_client_sock.sendall(MESSAGE_HEADER.pack(b'R', 4 + INT.size) + INT.pack(AUTHENTICATION_OK))

        header = json.loads(b64_decode(header_b64))
        payload = json.loads(b64_decode(payload_b64))


    def get_new_socket():
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    def recv_exactly(sock, amount):
        chunks = []
        while amount:
            chunk = sock.recv(min(amount, MAX_READ))
            chunks.append(chunk)
            amount -= len(chunks[-1])
        joined = b''.join(chunks)
        return joined

    sock = get_new_socket()
    sock.bind(("127.0.0.1", 7777))
    sock.listen(socket.IPPROTO_TCP)

    while True:
        client_sock, _ = sock.accept()
        gevent.spawn(handle_client_pre_tls, client_sock)
        client_sock = None  # To make sure we don't have it hanging around


def main():
    server()


if __name__ == "__main__":
    main()
