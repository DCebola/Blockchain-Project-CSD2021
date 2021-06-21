#!/bin/sh
while :
do
	docker stop replica-0 
	echo stop
	sleep 2 & wait
	docker start replica-0
	echo start
	sleep 2 & wait
done


