#!/bin/bash

if [ "$#" -eq 0 ]; then
    echo "Usage: build <n_faults> [-tls <key_type>]"
    exit 1
fi

F=$1
N=$((3*$F+1))

mvn clean package -f ../proxy
mvn clean package -f ../replica
mvn clean package -f ../client

sh bft/create_configs.sh $1 -tls $3
docker network create --driver=bridge --subnet=172.18.0.0/16 bftsmart-net
cd ../proxy && docker build . -t proxy
cd ../replica && docker build . -t replica
cd ../client && docker build . -t client
