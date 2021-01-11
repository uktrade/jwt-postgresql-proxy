#!/usr/bin/env bash

set -e

./generate-self-signed-cert.sh

SITE_PACKAGES_DIR=$(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")
echo "import coverage; coverage.process_startup()" > "${SITE_PACKAGES_DIR}/coverage.pth"
export COVERAGE_PROCESS_START=.coveragerc
python3 -m unittest "$@"
