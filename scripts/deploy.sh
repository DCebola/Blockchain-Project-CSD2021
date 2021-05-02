#!/bin/sh

if [ "$#" -ne 1 ]; then
    echo "Usage: deploy <n_faults>"
    exit 1
fi

F=$1
N=$((3*$F+1))
echo $N
