#!/bin/bash

cd "$(dirname "$0")"

echo "Setting up pythapi test environment..."
./pythapi.py install --debug-override-config "test/base_conf.ini" --reinstall -v 3
PYTHONPATH=. pytest $@ .
