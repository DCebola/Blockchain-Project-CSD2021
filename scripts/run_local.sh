#!/usr/bin/env bash
if [ "$#" -ne 1 ]; then
  echo "Usage: run_local <jar-name>" >&2
  exit 1
fi
java -jar target/"$1"