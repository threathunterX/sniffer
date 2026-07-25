#!/bin/bash
set -e

#export LC_ALL=zh_CN.UTF-8
# set env_variable to sniffer.conf and nebula.conf

###########log############
sed -i "s/>DEBUG</$DEBUG/" /home/nebula_sniffer/settings.py

###########global############
sed -i "s/>REDIS_HOST</$REDIS_HOST/" /home/nebula_sniffer/conf/*.conf
sed -i "s/>REDIS_PORT</$REDIS_PORT/" /home/nebula_sniffer/conf/*.conf
sed -i "s/>NEBULA_HOST</$NEBULA_HOST/" /home/nebula_sniffer/conf/*.conf
sed -i "s/>NEBULA_PORT</$NEBULA_PORT/" /home/nebula_sniffer/conf/*.conf

###########drivers############
##SOURCES
sed -i "s/>SOURCES</$SOURCES/" /home/nebula_sniffer/conf/sniffer.conf

##default
sed -i "s/>DRIVER_INTERFACE</$DRIVER_INTERFACE/" /home/nebula_sniffer/conf/sniffer.conf
sed -i "s/>DRIVER_PORT</$DRIVER_PORT/" /home/nebula_sniffer/conf/sniffer.conf
sed -i "s/>BRO_PORT</$BRO_PORT/" /home/nebula_sniffer/conf/sniffer.conf

##logstash
sed -i "s/>LOGSTASH_PORT</$LOGSTASH_PORT/" /home/nebula_sniffer/conf/sniffer.conf

##kafka
sed -i "s/>TOPICS</$TOPICS/" /home/nebula_sniffer/conf/sniffer.conf
sed -i "s/>GROUP_ID</$GROUP_ID/" /home/nebula_sniffer/conf/sniffer.conf
sed -i "s/>BOOTSTRAP_SERVERS</$BOOTSTRAP_SERVERS/" /home/nebula_sniffer/conf/sniffer.conf

##rabbitmq
sed -i "s/>AMQP_URL</$AMQP_URLT/" /home/nebula_sniffer/conf/sniffer.conf
sed -i "s/>AMQP_QUEUE_NAME</$AMQP_QUEUE_NAME/" /home/nebula_sniffer/conf/sniffer.conf
sed -i "s/>AMQP_EXCHANGE_NAME</$AMQP_EXCHANGE_NAME/" /home/nebula_sniffer/conf/sniffer.conf
sed -i "s/>AMQP_EXCHANGE_TYPE</$AMQP_EXCHANGE_TYPE/" /home/nebula_sniffer/conf/sniffer.conf
sed -i "s/>AMQP_DURABLE</$AMQP_DURABLE/" /home/nebula_sniffer/conf/sniffer.conf
sed -i "s/>AMQP_ROUTING_KEY</$AMQP_ROUTING_KEY/" /home/nebula_sniffer/conf/sniffer.conf

##redislist
sed -i "s/>REDIS_HOST</$REDIS_HOST/" /home/nebula_sniffer/conf/sniffer.conf
sed -i "s/>REDIS_PORT</$REDIS_PORT/" /home/nebula_sniffer/conf/sniffer.conf

##syslog
sed -i "s/>SYSLOG_PORT</$SYSLOG_PORT/" /home/nebula_sniffer/conf/sniffer.conf

exec "$@"
