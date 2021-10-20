# Distributed Decentralised Wallet Service (Java blockchain with Smart Contracts and Homomorphic Encription of transactions)

A distributed decentralised wallet service done as the class project for the CSD 2021 course. BFT SMaRT v1.2 was used to provide 
byzantine fault tolerance. The system provides **proxies**, **replicas** and a REST API.
It uses **REDIS** for persistant storage. A simple java command line client is provided to interact with the REST API.

## Security guarantees and observed vulnerabilities

The replicas communicate through mutual TLS. 

![Alt text](dump/replicas_handshake.png?raw=true)

The communication between replicas and redis and between the proxies and replicas is still not secure. This will be addressed in the short future. 

(Example: public key registration for a client being propagated to replicas from the proxy)

![Alt text](dump/replicas_proxy.png?raw=true)

(Example: communication with redis instance)

![Alt text](dump/replicas_redis.png?raw=true)


The java command line client communicates with the proxy with server side TLS.
Write operations are signed by the client and verified by the system's replicas. The proxy guarantees byzantine quorums of size 3f + 1 (with f being the number of tolerable byzantine faults). 

(Example: communication between proxy and java client)

![Alt text](dump/client_proxy.png?raw=true)


## Docker deployment

The proxies, replicas and redis can be deployed on docker. To do so we created three scripts that need to be run on the /scripts directory. (note we don't provide scripts to create the redis images, so firstly it is needed to pull the official docker image)



**[RESET]**

To stop and delete the containers, clean all packages and configs use **reset.sh**. *(note! if you have other running redis containers don't use the script as it might delete them)*



**[BUILD]**

To build the jars and configs run **build.sh <n_faults> [-tls <key_type>] <n_clients>**

Ex.1 To build a system that can tolerate 1 fault, uses TLS with ECDSA and creates 5 Client ECDSA key pairs on the java command line client (client1 with pass: client1Pass ... client5 with pass client5Pass)

**sh build.sh 1 -tls ECDSA 5**

Ex.2 To build a system that can tolerate 1 fault, uses TLS with RSA and creates 5 Client ECDSA key pairs on the java command line client (client1 with pass: client1Pass ... client5 with pass client5Pass)

**sh build.sh 1 -tls RSA 5**

note: BFTSMaRT is configured for benchmark so only one key pair is provided for RSA or ECDSA respectively: RSA_KeyPair_2048.pkcs12, EC_KeyPair_384.pkcs12



**[DEPLOY]**

(Note! ECDSA does not work with private transaction.)

To deploy the proxies, replicas, redis containers and sandboxes to a custom network use **deploy <n_proxies> <n_faults> [-tls <key_type>]**

Ex.1 To deploy a system that can tolerate 1 fault, uses TLS with ECDSA and creates 5 proxies

**sh deploy.sh 5 1 -tls ECDSA**

Ex.2 To deploy a system that can tolerate 1 fault, uses TLS with RSA and creates 5 proxies

**sh build.sh 5 1 -tls RSA**



**[Naming and IP conventions]**

We created a custom docker network **bftsmart-net** with a subnet 172.18.0.0/16.

The proxy container for the proxy with id n is named **proxy-n**, uses the ip **172.18.10.n** and exposes its **8443** port on **127.0.0.1:900n**.

The replica container for the replica with id n is named **replica-n**, uses the ip **172.18.20.n**.

The sandbox container for the sandbox with id n is named **sandbox-n**, uses the ip **172.18.20.2\*n**.

The redis container for the redis instance of the replica n is name **redis-n**, uses the ip **172.18.30.n**.

**[Simulation with Faults]**

Run the following script after deployment in the scripts directory: **sh start_faults.sh**


## Command line client

To run the command line client use **java -cp target/client-0.0.1-SNAPSHOT.jar -Dloader.main=com.clients.RestClient org.springframework.boot.loader.PropertiesLauncher <proxy port_to_connect>**
  
 ## Benchmark client

(Note! Benchmark client is outdated and is not compatible with recent version of the system, due to changes necessary for the transactions with privacy.)

To run the benchmark client use **java -cp target/client-0.0.1-SNAPSHOT.jar -Dloader.main=com.clients.BenchmarkClient org.springframework.boot.loader.PropertiesLauncher <proxy port_to_connect> <file with ops in resources folder> <key-alias> <key-pass> <extra_naming_arg>**
  
Each client will save its own results in a file located in the resources/benchamark_results in the client. The filename will have the following terminology:
  <file_with_ops_in_resouces_folder>_<key-alias>_results_<extra_naming_arg>.csv
  
<file with ops in resources folder> -> the file needs to be in the resources/benchmark_runs folder in the client. This argument must not include the full path.
  
In order to test the benchmark client execute first the following command: **java -cp target/client-0.0.1-SNAPSHOT.jar -Dloader.main=com.clients.BenchmarkClient org.springframework.boot.loader.PropertiesLauncher <proxy port_to_connect> registerClients**
  

 
  



Authors:

​	Diogo Cebola, 52718

​	Gonçalo Areia, 52714
