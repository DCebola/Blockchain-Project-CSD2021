#!/usr/bin/env bash
if [ "$#" -ne 1 ]; then
  echo "Usage: mvn_build <jar-name>" >&2
  exit 1
fi
mvn clean compile assembly:single
