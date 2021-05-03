#!/bin/bash

if [ "$#" -eq 0 ]; then
    echo "Usage: deploy <n_proxies> <n_faults> [-tls <key_type>]"
    exit 1
fi
P=$1
F=$2
N=$((3*$F+1))

for i in `seq $N`; do
    redis_ip="172.28.100.${i}"
    redis_name="redis-${i}"
    ip="172.28.20.${i}"
    container_name="replica-${i}"
    docker run --name $container_name -d replica java -Dlogback.configurationFile="./config/logback.xml" -jar replica.jar $i 
    docker network connect --ip $ip $container_name
    docker run --name $redis_name -d redis
    docker network connect --ip $redis_ip $redis_name
done

for i in `seq $P`; do
    port=$((9000+$i))
    ip="172.28.10.${i}"
    container_name="proxy-${i}"
    docker run --name $container_name -p $port:8443 -d proxy java -jar proxy.jar $i
    docker network connect --ip $ip $container_name
    #docker run client java -jar client.jar $i
done

