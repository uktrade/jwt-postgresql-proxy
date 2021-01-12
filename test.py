from base64 import urlsafe_b64encode
import contextlib
import json
import os
import socket
import subprocess
import time
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import psycopg2


private_key = load_pem_private_key(
    b'-----BEGIN PRIVATE KEY-----\n'
    b'MC4CAQAwBQYDK2VwBCIEINQG5lNt1bE8TZa68mV/WZdpqsXaOXBHvgPQGm5CcjHp\n'
    b'-----END PRIVATE KEY-----\n', password=None, backend=default_backend())


def with_application():
    def decorator(original_test):
        def test_with_application(self):
            process = subprocess.Popen(
                ['python3', '-m', 'jwt_postgresql_proxy'],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                env={
                    **os.environ,
                    'PUBLIC_KEYS__1': (
                        '-----BEGIN PUBLIC KEY-----\n'
                        'MCowBQYDK2VwAyEAe9+zIz+CH9E++J0qiE6aS657qzxsNWIEf2BZcUAQF94=\n'
                        '-----END PUBLIC KEY-----\n'
                    ),
                    'UPSTREAM__HOST': 'localhost',
                    'UPSTREAM__PORT': '5432',
                    'UPSTREAM__PASSWORD': 'password',
                    'DOWNSTREAM__IP': '127.0.0.1',
                    'DOWNSTREAM__PORT': '7777',
                    'DOWNSTREAM__CERTFILE': 'server.crt',
                    'DOWNSTREAM__KEYFILE': 'server.key',
                }
            )

            def stop():
                process.kill()
                process.wait(timeout=5)
                process.stderr.close()
                process.stdout.close()

            def ensure_can_connect_to(port):
                for i in range(0, 100):
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                            break
                    except (OSError, ConnectionRefusedError):
                        if i == 100 - 1:
                            raise
                        time.sleep(0.02)
            try:
                ensure_can_connect_to(7777)
                ensure_can_connect_to(5432)
                original_test(self)
            finally:
                stop()

        return test_with_application

    return decorator


@contextlib.contextmanager
def get_conn(dsn):
    conn = psycopg2.connect(dsn)
    try:
        yield conn
    finally:
        conn.close()


def b64encode_nopadding(to_encode):
    return urlsafe_b64encode(to_encode).rstrip(b'=')


class TestProxy(unittest.TestCase):

    @with_application()
    def test_select(self):
        header = {
            'typ': 'JWT',
            'alg': 'EdDSA',
            'crv': 'Ed25519',
        }
        payload = {
            'sub': 'postgres',
            'exp': int(time.time() + 60 * 60 * 24),
        }
        to_sign = b64encode_nopadding(json.dumps(header).encode(
            'utf-8')) + b'.' + b64encode_nopadding(json.dumps(payload).encode('utf-8'))
        signature = b64encode_nopadding(private_key.sign(to_sign))
        jwt = (to_sign + b'.' + signature).decode()

        dsn = \
            f'dbname=postgres user=postgres password={jwt} host=127.0.0.1 port=7777 ' \
            'sslmode=require'

        with \
                get_conn(dsn) as conn, \
                conn.cursor() as cur:
            cur.execute('SELECT 1,3,4')
            results = cur.fetchall()

        self.assertEqual(results, [(1, 3, 4)])
