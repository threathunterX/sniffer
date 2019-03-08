#!/bin/bash
set -e

#export LC_ALL=zh_CN.UTF-8
# set env_variable to sniffer.conf and nebula.conf
sed -i "s/>DEBUG</$DEBUG/" /home/nebula_sniffer/settings.py
sed -i "s/>REDIS_HOST</$REDIS_HOST/" /home/nebula_sniffer/conf/*.conf
sed -i "s/>REDIS_PORT</$REDIS_PORT/" /home/nebula_sniffer/conf/*.conf
sed -i "s/>NEBULA_HOST</$NEBULA_HOST/" /home/nebula_sniffer/conf/*.conf
sed -i "s/>NEBULA_PORT</$NEBULA_PORT/" /home/nebula_sniffer/conf/*.conf
sed -i "s/>DRIVER_INTERFACE</$DRIVER_INTERFACE/" /home/nebula_sniffer/conf/*.conf
sed -i "s/>DRIVER_PORT</$DRIVER_PORT/" /home/nebula_sniffer/conf/*.conf
exec "$@"
