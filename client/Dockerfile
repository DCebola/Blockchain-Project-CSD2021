# base image - an image with openjdk  8
FROM openjdk:11

# working directory inside docker image
WORKDIR .

# copy the jar created by assembly to the docker image
COPY target/wa-1-server.jar wa-1-server.jar

CMD ["java", "-jar", "wa-1-server.jar"]
