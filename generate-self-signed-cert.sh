#!/usr/bin/env bash

set -e

openssl req  -nodes -new -x509 -subj "/CN=localhost" -keyout server.key -out server.cert
