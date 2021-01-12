from gevent import monkey
monkey.patch_all()

from base64 import urlsafe_b64decode
from hashlib import md5
import itertools
import os
import re
import gevent
import json
import socket
import ssl
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key


class ConnectionClosed(Exception):
    pass


class ProtocolError(Exception):
    pass


class AuthenticationError(Exception):
    pass


def main():
    env = normalise_environment(os.environ)
    UPSTREAM__HOST = env['UPSTREAM']['HOST']
    UPSTREAM__PORT = env['UPSTREAM']['PORT']
    UPSTREAM__PASSWORD = env['UPSTREAM']['PASSWORD']
    DOWNSTREAM__IP = env['DOWNSTREAM']['IP']
    DOWNSTREAM__PORT = env['DOWNSTREAM']['PORT']
    DOWNSTREAM__CERTFILE = env['DOWNSTREAM']['CERTFILE']
    DOWNSTREAM__KEYFILE = env['DOWNSTREAM']['KEYFILE']
    PUBLIC_KEYS = env['PUBLIC_KEYS']

    TLS_REQUEST = b'\x00\x00\x00\x08\x04\xd2\x16/'
    TLS_RESPONSE = b'S'

    STARTUP_MESSAGE_HEADER = struct.Struct('!LL')
    MESSAGE_HEADER = struct.Struct('!cL')
    INT = struct.Struct('!L')

    PROTOCOL_VERSION = 196608

    AUTHENTICATION_CLEARTEXT_PASSWORD = 3
    AUTHENTICATION_MD5_PASSWORD = 5
    AUTHENTICATION_OK = 0
    PASSWORD_RESPONSE = b'p'

    MAX_READ = 66560
    MAX_IN_MEMORY_MESSAGE_LENGTH = 66560

    ssl_context_downstream = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ssl_context_downstream.load_cert_chain(
        certfile=DOWNSTREAM__CERTFILE, keyfile=DOWNSTREAM__KEYFILE)

    ssl_context_upstream = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ssl_context_upstream.verify_mode = ssl.CERT_NONE

    public_keys = [
        load_pem_public_key(public_key.encode(), backend=default_backend())
        for public_key in PUBLIC_KEYS
    ]

    def b64_decode(b64_bytes):
        return urlsafe_b64decode(b64_bytes + (b'=' * ((4 - len(b64_bytes) % 4) % 4)))

    def handle_downstream(downstream_sock):
        # The high level logic of connection, authentication, and proxying, is all here

        downstream_sock_ssl = None
        upstream_sock = None
        upstream_sock_ssl = None

        try:
            # Initiate TLS
            downstream_sock_ssl = downstream_convert_to_ssl(downstream_sock)

            # Startup PostgreSQL downstream
            user, database = downstream_startup(downstream_sock_ssl)

            # Authenticate downstream user
            downstream_authenticate(downstream_sock_ssl, user)

            # Connect on TCP level upstream
            upstream_sock = upstream_connect()

            # Convert upstream to TLS
            upstream_sock_ssl = upstream_convert_to_ssl(upstream_sock)

            # Startup PostgreSQL upstream
            upstream_startup(upstream_sock_ssl, user, database)

            # Authenticate upstream user
            upstream_authenticate(upstream_sock_ssl, user)

            # Run proxy
            proxy_both_directions(downstream_sock_ssl, upstream_sock_ssl)

        except AuthenticationError:
            downstream_send_auth_error(downstream_sock_ssl or downstream_sock)

        except ProtocolError:
            downstream_send_error(downstream_sock_ssl or downstream_sock)

        finally:
            # Slightly faffy cleanup to deal the various cases where things could have stopped
            # at various points in the process

            if upstream_sock_ssl is not None:
                try:
                    upstream_sock = upstream_sock_ssl.unwrap()
                except (OSError, ssl.SSLError):
                    pass

            if upstream_sock is not None:
                try:
                    upstream_sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    # Could have shutdown already
                    pass
                finally:
                    upstream_sock.close()

            if downstream_sock_ssl is not None:
                try:
                    downstream_sock = downstream_sock_ssl.unwrap()
                except (OSError, ssl.SSLError):
                    pass

            try:
                downstream_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                # Could have shutdown already
                pass
            finally:
                downstream_sock.close()

    def downstream_convert_to_ssl(downstream_sock):
        chunk = recv_exactly(downstream_sock, len(TLS_REQUEST))
        if chunk != TLS_REQUEST:
            downstream_sock.sendall(MESSAGE_HEADER.pack(b'E', 4 + 1) + b'\x00')
            raise ProtocolError()
        downstream_sock.sendall(TLS_RESPONSE)
        downstream_sock_ssl = ssl_context_downstream.wrap_socket(downstream_sock, server_side=True)
        return downstream_sock_ssl

    def downstream_startup(downstream_sock_ssl):
        startup_message_len, protocol_version = STARTUP_MESSAGE_HEADER.unpack(
            recv_exactly(downstream_sock_ssl, STARTUP_MESSAGE_HEADER.size))
        if startup_message_len > MAX_IN_MEMORY_MESSAGE_LENGTH:
            raise ProtocolError('Startup message too large')

        if protocol_version != PROTOCOL_VERSION:
            downstream_sock_ssl.sendall(MESSAGE_HEADER.pack(b'E', 4 + 1) + b'\x00')
            raise ProtocolError('Unsupported downstream protocol version')

        startup_key_value_pairs = recv_exactly(
            downstream_sock_ssl, startup_message_len - STARTUP_MESSAGE_HEADER.size)

        pairs = dict(re.compile(b'([^\x00]+)\x00([^\x00]*)').findall(startup_key_value_pairs))

        return pairs[b'user'].decode(), pairs[b'database'].decode()

    def downstream_authenticate(downstream_sock_ssl, claimed_user):
        # Request password
        downstream_sock_ssl.sendall(MESSAGE_HEADER.pack(b'R', 4 + INT.size)
                                    + INT.pack(AUTHENTICATION_CLEARTEXT_PASSWORD))

        # Get password response
        tag, payload_length = MESSAGE_HEADER.unpack(
            recv_exactly(downstream_sock_ssl, MESSAGE_HEADER.size))
        if payload_length > MAX_IN_MEMORY_MESSAGE_LENGTH:
            raise ProtocolError('Password response message too large')
        if tag != PASSWORD_RESPONSE:
            raise ProtocolError('Expected password to request for password')
        password = (recv_exactly(downstream_sock_ssl, payload_length - 4))[:-1]

        # Verify signature
        header_b64, payload_b64, signature_b64 = password.split(b'.')
        for public_key in public_keys:
            try:
                # pylint: disable=no-value-for-parameter
                public_key.verify(b64_decode(signature_b64), header_b64 + b'.' + payload_b64)
            except InvalidSignature:
                continue
            else:
                break
        else:
            raise AuthenticationError()

        # Ensure the signed JWT `sub` is the same as the claimed database user
        payload = json.loads(b64_decode(payload_b64))
        if claimed_user != payload['sub']:
            raise AuthenticationError()

        now = time.time()
        if payload['exp'] <= now:
            raise AuthenticationError()

        # Tell downstream we are authenticated
        downstream_sock_ssl.sendall(MESSAGE_HEADER.pack(
            b'R', 4 + INT.size) + INT.pack(AUTHENTICATION_OK))

    def downstream_send_auth_error(downstream_sock):
        failed = \
            b'S' + b'FATAL\x00' + \
            b'M' + b'Authentication failed\x00' + \
            b'C' + b'28P01\x00' + \
            b'\x00'
        downstream_sock.sendall(MESSAGE_HEADER.pack(b'E', 4 + len(failed)) + failed)

    def downstream_send_error(downstream_sock):
        downstream_sock.sendall(MESSAGE_HEADER.pack(b'E', 4 + 1) + b'\x00')

    def upstream_connect():
        upstream_sock = socket.create_connection((UPSTREAM__HOST, UPSTREAM__PORT))
        upstream_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return upstream_sock

    def upstream_convert_to_ssl(upstream_sock):
        upstream_sock.sendall(TLS_REQUEST)
        response = recv_exactly(upstream_sock, len(TLS_RESPONSE))
        if response != TLS_RESPONSE:
            raise ProtocolError()

        upstream_sock_ssl = ssl_context_upstream.wrap_socket(upstream_sock)
        return upstream_sock_ssl

    def upstream_startup(upstream_sock_ssl, user, database):
        pairs = \
            b'user\x00' + user.encode() + b'\x00' + \
            b'database\x00' + database.encode() + b'\x00' + \
            b'\x00'
        upstream_sock_ssl.sendall(
            STARTUP_MESSAGE_HEADER.pack(8 + len(pairs), PROTOCOL_VERSION) + pairs
        )

    def upstream_authenticate(upstream_sock_ssl, user):
        tag, message_len = MESSAGE_HEADER.unpack(
            recv_exactly(upstream_sock_ssl, MESSAGE_HEADER.size))
        message = recv_exactly(upstream_sock_ssl, message_len - 4)
        if tag != b'R':
            raise ProtocolError()

        auth_method, = INT.unpack(message[:4])

        # We only support MD5 password exchange
        if auth_method != AUTHENTICATION_MD5_PASSWORD:
            raise ProtocolError()

        salt = message[4:]
        hashed_password = b'md5' + \
            md5(md5(UPSTREAM__PASSWORD.encode() + user.encode()).hexdigest().encode()
                + salt).hexdigest().encode() + b'\x00'

        upstream_sock_ssl.sendall(MESSAGE_HEADER.pack(
            PASSWORD_RESPONSE, 4 + len(hashed_password)) + hashed_password)

        tag, message_len = MESSAGE_HEADER.unpack(
            recv_exactly(upstream_sock_ssl, MESSAGE_HEADER.size))
        message = recv_exactly(upstream_sock_ssl, message_len - 4)

        if tag != b'R':
            raise AuthenticationError()
        auth_result, = INT.unpack(message)
        if auth_result != AUTHENTICATION_OK:
            raise AuthenticationError()

    def proxy_both_directions(sock_a, sock_b):
        done = gevent.event.Event()

        def _proxy(source, target):
            try:
                while chunk := source.recv(MAX_READ):
                    target.sendall(chunk)
            finally:
                done.set()

        a_to_b_greenlet = gevent.spawn(_proxy, sock_a, sock_b)
        b_to_a_greenlet = gevent.spawn(_proxy, sock_b, sock_a)
        done.wait()

        a_to_b_greenlet.kill()
        b_to_a_greenlet.kill()
        a_to_b_greenlet.join()
        b_to_a_greenlet.join()

    def get_new_socket():
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM,
                             proto=socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    def recv_exactly(sock, amount):
        chunks = []
        while amount:
            chunk = sock.recv(min(amount, MAX_READ))
            if chunk:
                chunks.append(chunk)
                amount -= len(chunks[-1])
            else:
                raise Exception()
        joined = b''.join(chunks)
        return joined

    sock = get_new_socket()
    sock.bind((DOWNSTREAM__IP, int(DOWNSTREAM__PORT)))
    sock.listen(socket.IPPROTO_TCP)

    while True:
        downstream_sock, _ = sock.accept()
        gevent.spawn(handle_downstream, downstream_sock)
        downstream_sock = None  # To make sure we don't have it hanging around


def normalise_environment(key_values):
    separator = '__'

    def get_first_component(key):
        return key.split(separator)[0]

    def get_later_components(key):
        return separator.join(key.split(separator)[1:])

    without_more_components = {
        key: value
        for key, value in key_values.items()
        if not get_later_components(key)
    }

    with_more_components = {
        key: value
        for key, value in key_values.items()
        if get_later_components(key)
    }

    def grouped_by_first_component(items):
        def by_first_component(item):
            return get_first_component(item[0])

        return itertools.groupby(
            sorted(items, key=by_first_component),
            by_first_component,
        )

    def items_with_first_component(items, first_component):
        return {
            get_later_components(key): value
            for key, value in items
            if get_first_component(key) == first_component
        }

    nested_structured_dict = {
        **without_more_components, **{
            first_component: normalise_environment(
                items_with_first_component(items, first_component))
            for first_component, items in grouped_by_first_component(with_more_components.items())
        }}

    def all_keys_are_ints():
        def is_int(string):
            try:
                int(string)
                return True
            except ValueError:
                return False

        return all([is_int(key) for key, value in nested_structured_dict.items()])

    def list_sorted_by_int_key():
        return [
            value
            for key, value in sorted(
                nested_structured_dict.items(),
                key=lambda key_value: int(key_value[0])
            )
        ]

    return \
        list_sorted_by_int_key() if all_keys_are_ints() else \
        nested_structured_dict


if __name__ == '__main__':
    main()
