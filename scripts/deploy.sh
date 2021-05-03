#!/bin/bash

if [ "$#" -eq 0 ]; then
    echo "Usage: deploy <n_faults> [-tls <key_type>]"
    exit 1
fi

F=$1
N=$((3*$F+1))
KEY_TYPE=$3

#mvn clean package -f ../proxy
#mvn clean package -f ../replica
#mvn clean package -f ../client

sh bft/create_configs.sh $F -tls $KEY_TYPE

#for i in `seq $N`; do
#    REPLICA_ID=$i docker-compose -f docker/replica-docker-compose.yml up -d
#    docker exec replica-$i java -Dlogback.configurationFile="./config/logback.xml" -jar replica.jar $i
#done

PROXY_ID=1 docker-compose -f docker/proxy-docker-compose.yml up -d
docker run proxy-1 java -jar proxy.jar 1 connect  -ip 
