#!/bin/sh

if [ "$#" -eq 0 ]; then
    echo "Usage: deploy <n_faults> [-tls <key_type>]"
    exit 1
fi

F=$1
N=$((3*$F+1))
KEY_TYPE=$3

mvn clean compile -f ../proxy
mvn clean compile -f ../replica
mvn clean compile -f ../client

sh bft/create_configs.sh $F -tls $KEY_TYPE

PROXY-ID=1 docker-compose -f docker/proxy-docker-compose.yml up

for i in `seq $N`; do
    REPLICA-ID=$i docker-compose -f docker/proxy-docker-compose.yml up
done

