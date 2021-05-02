# base image - an image with openjdk  8
FROM openjdk:11

# working directory inside docker image
WORKDIR .

# copy the jar created by assembly to the docker image
COPY target/demo-0.0.1-SNAPSHOT.jar client.jar

CMD ["java", "-cp", "client.jar", "-Dloader.main=com.clients.RestClient", "org.springframework.boot.loader.PropertiesLauncher" ]
