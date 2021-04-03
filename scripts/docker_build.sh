#!/usr/bin/env bash
if [ "$#" -ne 1 ]; then
  echo "Usage: docker_build <image-name>" >&2
  exit 1
fi
docker build -t "$1" .