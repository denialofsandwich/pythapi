#!/bin/bash

cd "$(dirname "$0")"
P=${1:-.}
shift

PYTHONPATH=. pytest --cov=. $P --cov-report term-missing $@
