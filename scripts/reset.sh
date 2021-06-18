#!/bin/sh

mvn clean -f ../proxy
mvn clean -f ../replica
mvn clean -f ../client
mvn clean -f ../sandbox

rm -rf ../client/config
rm ../client/src/main/resources/*.jks 
rm ../client/src/main/resources/SmartContract.class 
rm -rf ../proxy/config
rm -rf ../replica/config
rm -rf ../sandbox/config

docker rm $(docker stop $(docker ps -a -q --filter ancestor=replica))
docker rm $(docker stop $(docker ps -a -q --filter ancestor=proxy))
docker rm $(docker stop $(docker ps -a -q --filter ancestor=sandbox))
docker rm $(docker stop $(docker ps -a -q --filter ancestor=redis))
docker image rmi proxy
docker image rmi replica
docker image rmi sandbox
docker network remove bftsmart-net


