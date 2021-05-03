# base image - an image with openjdk  8
FROM openjdk:11

# working directory inside docker image
WORKDIR .

COPY config config

# copy the jar created by assembly to the docker image
COPY target/proxy-0.0.1-SNAPSHOT.jar proxy.jar
