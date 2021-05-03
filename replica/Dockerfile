# base image - an image with openjdk  8
FROM openjdk:11

# working directory inside docker image
WORKDIR .

COPY config config

# copy the jar created by assembly to the docker image
COPY target/replica-jar-with-dependencies.jar replica.jar
