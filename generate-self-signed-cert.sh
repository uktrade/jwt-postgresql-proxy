#!/usr/bin/env bash

set -e

openssl genrsa -des3 -out server.key 2048
openssl rsa -in server.key -out server.key
openssl req -new -key server.key -days 3650 -out server.crt -x509 -subj "/CN=Common Name"
