# base image - an image with openjdk  8
FROM openjdk:11

# working directory inside docker image
WORKDIR .

# copy the jar created by assembly to the docker image
COPY target/wa-1-server.jar wa-1-server.jar
# copy configs
COPY target/resources/ resources/

# copy the file of properties to the docker image
#COPY messages.props messages.props

# run Discovery when starting the docker image
CMD ["java", "-Djavax.net.ssl.keyStore=resources/server.ks", "-Djavax.net.ssl.keyStorePassword=password", "-Djavax.net.ssl.trustStore=resources/truststore.ks", "-Djavax.net.ssl.trustStorePassword=changeit", "-cp", "wa-1-server.jar", "main.java.bftsmart.app.BFTSmartClient"]

