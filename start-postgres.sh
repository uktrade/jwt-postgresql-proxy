#!/usr/bin/env bash

# No volumes, so can have a very similar command in CircleCI
docker run --rm -it --name jwt-postgresql-upstream \
    -e POSTGRES_PASSWORD=password \
    -p 5432:5432 \
    --entrypoint bash \
    postgres:9.6.7 \
    -c 'openssl req -nodes -new -x509 -subj "/CN=localhost" -keyout server.key -out server.crt && \
        chown postgres server.key && \
        chmod 600 /server.key && \
        exec /docker-entrypoint.sh -c ssl=on -c ssl_cert_file=/server.crt -c ssl_key_file=/server.key'
