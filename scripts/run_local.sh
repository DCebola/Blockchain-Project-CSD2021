#!/usr/bin/env bash
if [ "$#" -ne 1 ]; then
  echo "Usage: run_local <jar-name>" >&2
  exit 1
fi
java -Djavax.net.ssl.keyStore=./server.ks -Djavax.net.ssl.keyStorePassword=password -Djavax.net.ssl.trustStore=./truststore.ks, -Djavax.net.ssl.trustStorePassword=changeit -jar target/"$1"
