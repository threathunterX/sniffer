#!/bin/bash
# 启动sniffer脚本
sudo killall bro
sudo ps -aef | grep "python sniffer.py"  | awk '{print $2}'  | xargs kill -9
sudo source venv/bin/activate
sudo nohup venv/bin/python sniffer.py > ./output.log 2>&1 &