#!/bin/bash

mkdir -p venv

python3 -m venv "./venv"
source ./venv/bin/activate

pip3 install -r requirements.txt

./pull-tester/rpc-tests.py "$@"
