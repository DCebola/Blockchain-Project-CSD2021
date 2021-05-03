#!/bin/sh

mvn clean -f ../proxy
mvn clean -f ../replica
mvn clean -f ../client

rm -rf ../client/config
rm ../client/src/main/resources/*.jks 
rm -rf ../proxy/config
rm -rf ../replica/config

docker rm $(docker stop $(docker ps -a -q --filter ancestor=replica))
docker rm $(docker stop $(docker ps -a -q --filter ancestor=proxy))
docker rm $(docker stop $(docker ps -a -q --filter ancestor=client))
docker rm $(docker stop $(docker ps -a -q --filter ancestor=redis))
docker image rmi proxy
docker image rmi replica
docker network remove bftsmart-net


