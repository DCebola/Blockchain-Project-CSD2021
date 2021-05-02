#!/bin/sh

mvn clean -f ../proxy
mvn clean -f ../replica
mvn clean -f ../client

rm -rf ../client/config
rm -rf ../proxy/config
rm -rf ../replic/config
