# jwt-postgresql-proxy

PostgreSQL proxy that puts stateless JWT authentication in front of PostgreSQL

> This is a work-in-progress. This README serves as a rough design spec.


## Use case

You have a PostgreSQL database, and would like to frequently issue temporary credentials to a set of users, where a single real-world user can have a number of temporary credentials issued at any given moment. This can be done just with PostgreSQL, but involves work-arounds:

- GRANTing multiple permissions at the same time can result in "tuple concurrently updated" errors, requiring explicit locking to avoid, and so can be slow when there are multiple users attempting to get credentials for a high number of database objects at any one time.

- For objects created by the temporary database users, ownership has to be transferred, for example by database triggers, to a permanent role for the real-world user.

This proxy avoids having to do the above workarounds:

- Database credentials are issued as a temporary stateless JWT token, by code that holds a private key.

- Instead of connecting directly to the database, users connect to this proxy. It verifies the credentials using the corresponding public key, and connects to the database as the permanent database user, the the credentials of which the real-world user never knows.

The JWT token being _stateless_ means that the issuer of credentials does not need to communicate with the proxy via some internal API, and this proxy does not need a database to store credentials.


## Development environment

```
python3 -m venv env
source env/bin/activate
```
