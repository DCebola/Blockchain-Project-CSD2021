#!/bin/sh
if [ $# -ne 1 ]; then
    echo "Usage: create_configs.sh <n_faults>"
    exit 1
fi
F=$1
N=$((3*$F+1))
cd ./bft
mkdir ecdsakeys
for i in `seq $N`; do
    java -Dlogback.configurationFile="../../replica/config/logback.xml" -cp ../../replica/target/replica-jar-with-dependencies.jar bftsmart.tom.util.ECDSAKeyPairGenerator $i secp384r1
done

cp ecdsakeys ../../replica/config
mv ecdsakeys ../../proxy/config
cd ..
