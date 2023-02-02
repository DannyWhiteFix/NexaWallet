#!/bin/bash
set -e
docker build --no-cache -f Dockerfile.ubuntu20-1.1 -t bchunlimited/nexa-1.1:ubuntu20.04 .
docker push bchunlimited/nexa-1.1:ubuntu20.04
