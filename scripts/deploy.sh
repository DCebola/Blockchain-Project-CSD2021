#!/bin/bash

if [ "$#" -eq 0 ]; then
    echo "Usage: deploy <n_proxies> <n_faults> [-tls <key_type>]"
    exit 1
fi
P=$1
F=$2
N=$((3*$F+1))

for i in `seq $N`; do
    redis_ip="172.18.30.$(( $i - 1 ))"
    redis_name="redis-$(( $i - 1 ))"
    ip="172.18.20.${i}"
    container_name="replica-$(( $i - 1 ))"
    docker run --network bftsmart-net --ip $ip --name $container_name -d replica java -Dlogback.configurationFile="./config/logback.xml" -jar replica.jar $(( $i - 1 )) 

    docker run --network bftsmart-net --ip $redis_ip --name $redis_name -d redis

done

for i in `seq $P`; do
    port=$((9000+$i))
    ip="172.18.10.${i}"
    container_name="proxy-${i}"
    docker run --network bftsmart-net --ip $ip --name $container_name -p "127.0.0.1:${port}":8443 -d proxy java -jar proxy.jar $i
done

