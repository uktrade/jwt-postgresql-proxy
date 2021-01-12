# jwt-postgresql-proxy [![CircleCI](https://circleci.com/gh/uktrade/jwt-postgresql-proxy.svg?style=svg)](https://circleci.com/gh/uktrade/jwt-postgresql-proxy) [![Test Coverage](https://api.codeclimate.com/v1/badges/ff380168c33456b7a248/test_coverage)](https://codeclimate.com/github/uktrade/jwt-postgresql-proxy/test_coverage)

Stateless JWT authentication in front of PostgreSQL


## Use case

You have a PostgreSQL database, and would like to frequently issue temporary credentials to a set of users, where a single real-world user can have a number of temporary credentials issued at any given moment. This can be done just with PostgreSQL, but involves work-arounds:

- GRANTing multiple permissions at the same time can result in "tuple concurrently updated" errors, requiring explicit locking to avoid, and so can be slow when there are multiple users attempting to get credentials for a high number of database objects at any one time.

- For objects created by the temporary database users, ownership has to be transferred, for example by database triggers, to a permanent role for the real-world user.

This proxy avoids having to do the above workarounds:

- Database credentials are issued as a temporary stateless JWT token, by code that holds a private key.

- Instead of connecting directly to the database, users connect to this proxy. It verifies the credentials using the corresponding public key, and connects to the database as the permanent database user, the credentials of which the real-world user never knows.

The JWT token being _stateless_ means that the issuer of credentials does not need to communicate with the proxy via some internal API, and this proxy does not need a database to store credentials.


## Usage: Issuing and using credentials

An Ed25519 public/private key pair needs to be created, for example using the [Python cryptography package](https://github.com/pyca/cryptography):

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

private_key = Ed25519PrivateKey.generate()
print(private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()))
print(private_key.public_key().public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo))
```

The issuer of credentials would use the private key to create a JWT for a database user, such as in the below Python example for the database user `my_user` for the next 24 hours.

```python
from base64 import urlsafe_b64encode
import json
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def b64encode_nopadding(to_encode):
    return urlsafe_b64encode(to_encode).rstrip(b'=')

private_key = load_pem_private_key(
    # In real cases, take the private key from an environment variable or secret store
    b'-----BEGIN PRIVATE KEY-----\n' \
    b'MC4CAQAwBQYDK2VwBCIEINQG5lNt1bE8TZa68mV/WZdpqsXaOXBHvgPQGm5CcjHp\n' \
    b'-----END PRIVATE KEY-----\n', password=None, backend=default_backend())
header = {
    'typ': 'JWT',
    'alg': 'EdDSA',
    'crv': 'Ed25519',
}
payload = {
    'sub': 'my_user',
    'exp': int(time.time() + 60 * 60 * 24),
}
to_sign = b64encode_nopadding(json.dumps(header).encode('utf-8')) + b'.' + b64encode_nopadding(json.dumps(payload).encode('utf-8'))
signature = b64encode_nopadding(private_key.sign(to_sign))
jwt = (to_sign + b'.' + signature).decode()
print(jwt)
```

The JWT can be given to the real-world user, and used as the PostgreSQL password to connect to the proxy as `my_user`.

```python
import psycopg2

jwt = 'eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJFZERTQSIsICJjcnYiOiAiRWQyNTUxOSJ9.eyJzdWIiOiAibXlfdXNlciIsICJleHAiOiAxNjEwNTYxOTYxfQ.YeTn4oYwOvQLApTg2WgldX--qRywM0MV-EoDdL7ZNr0HnoadxZ9wKt_fqqT7L8w1d378UtaXavq0B_LUYUt4Dg'
conn = psycopg2.connect(password=jwt, user='my_user', host='host-of-the-proxy', dbname='my_dbname', port=5432)
```


## Usage: installing, configuring, and running the proxy

To install, Python `pip` is used

```bash
pip install jwt-postgresql-proxy
```

Configuration is done via environment variables. All of the below environment variables are required.

| Variable            | Description                                                                                                                                                                                                                                                                                        |
|---------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| PUBLIC_KEYS__i       | For any integer `i`, a public key corresponding to the private key used to sign the JWTs used by clients as the PostgreSQL password. Multiple keys are allowed at any given time to allow for key rotation. Each key must be in PEM format, and have no password.                          |
| UPSTREAM__HOST       | The host of the database that the proxy connects to.                                                                                                                                                                                                                                               |
| UPSTREAM__PORT       | The port of the database that the proxy connects to.                                                                                                                                                                                                                                               |
| UPSTREAM__PASSWORD   | The password of the database that the proxy connects to. Note that all users that the proxy connects to on the database must have the same password. While unusual, this isn't materially different to always connecting as the same "master" user which has a single password, which is a typical pattern. |
| DOWNSTREAM__IP       | The IP of the network interface to listen on for incoming connections. This is empty to listen on all interfaces, or `127.0.0.1` to listen only for connections on localhost. |
| DOWNSTREAM__PORT     | The port to listen on for incoming connections. Typically, this is `5432`. |
| DOWNSTREAM__CERTFILE | The path to the certificate presented to incoming downstream connections. |
| DOWNSTREAM__KEYFILE  | The path to the private key used in downstream connections. |

If you wish, the files at `DOWNSTREAM__CERTFILE` and `DOWNSTREAM__KEYFILE` can be self-signed, and generated using the command

```bash
openssl req -nodes -new -x509 -subj "/CN=my.dbhost.test" -keyout server.key -out server.crt
```

To start the proxy

```bash
jwt-postgresql-proxy
```


## Tests

```bash
./start-postgres.sh  # Only needs to be done once
./test.sh
```
