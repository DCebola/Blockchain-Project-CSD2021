#!/bin/sh
while :
do
	docker stop replica-0 
	echo stop
	sleep 1 & wait
	docker start replica-0
	echo start
	sleep 0.5 & wait
done


