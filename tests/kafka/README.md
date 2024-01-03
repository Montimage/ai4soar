```
$ sudo docker-compose -f docker-compose.yml up -d

$ sudo docker exec -it kafka /bin/sh
# ls /opt/
kafka  kafka_2.13-2.8.1  overrides
# cd /opt/kafka_2.13-2.8.1/bin
# ls
connect-distributed.sh	      kafka-dump-log.sh			   kafka-storage.sh
connect-mirror-maker.sh       kafka-features.sh			   kafka-streams-application-reset.sh
connect-standalone.sh	      kafka-leader-election.sh		   kafka-topics.sh
kafka-acls.sh		      kafka-log-dirs.sh			   kafka-verifiable-consumer.sh
kafka-broker-api-versions.sh  kafka-metadata-shell.sh		   kafka-verifiable-producer.sh
kafka-cluster.sh	      kafka-mirror-maker.sh		   trogdor.sh
kafka-configs.sh	      kafka-preferred-replica-election.sh  windows
kafka-console-consumer.sh     kafka-producer-perf-test.sh	   zookeeper-security-migration.sh
kafka-console-producer.sh     kafka-reassign-partitions.sh	   zookeeper-server-start.sh
kafka-consumer-groups.sh      kafka-replica-verification.sh	   zookeeper-server-stop.sh
kafka-consumer-perf-test.sh   kafka-run-class.sh		   zookeeper-shell.sh
kafka-delegation-tokens.sh    kafka-server-start.sh
kafka-delete-records.sh       kafka-server-stop.sh

# kafka-topics.sh --create --zookeeper zookeeper:2181 --replication-factor 1 --partitions 1 --topic ai4soar_kafka_topic
WARNING: Due to limitations in metric names, topics with a period ('.') or underscore ('_') could collide. To avoid issues it is best to use either, but not both.
Created topic ai4soar_kafka_topic.
# kafka-topics.sh --list --zookeeper zookeeper:2181
ai4soar_kafka_topic

# kafka-console-producer.sh --bootstrap-server localhost:9092 --topic ai4soar_kafka_topic
hello
>>how are you
>merci
>exit
```

```
$ python3 --version
Python 3.8.10
$ sudo apt install python3-pip
$ pip3 --version
pip 20.0.2 from /usr/lib/python3/dist-packages/pip (python 3.8)

$ pip3 install Flask kafka-python confluent_kafka
$ python3 server.py
 * Serving Flask app 'server'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 158-808-424
Received Kafka message: hello
Received Kafka message: how are you
Received Kafka message: merci
Received Kafka message: exit
```
