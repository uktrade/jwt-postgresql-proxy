import os
import socket
import subprocess
import time
import unittest


def with_application():
    def decorator(original_test):
        def test_with_application(self):
            process = subprocess.Popen(
                ['python3', '-m', 'jwt_postgresql_proxy'],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                env={
                    **os.environ,
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

            try:
                for i in range(0, 100):
                    try:
                        with socket.create_connection(('127.0.0.1', '7777'), timeout=0.1):
                            break
                    except (OSError, ConnectionRefusedError):
                        if i == 100 - 1:
                            raise
                        time.sleep(0.02)
                original_test(self)
            finally:
                stop()

        return test_with_application

    return decorator


class TestProxy(unittest.TestCase):

    @with_application()
    def test_dummy(self):
        self.assertTrue(1 > 0)
