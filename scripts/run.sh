#!/usr/bin/env bash
if [ "$#" -ne 1 ]; then
  echo "Usage: run <image-name>" >&2
  exit 1
fi
docker run --network csdnet -p 8080:8080 "$1"
