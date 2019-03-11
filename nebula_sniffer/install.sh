#/sbin/bash
# note 此脚本便于安装sniffer,前提为当前文件夹下有bro文件夹
sudo yum -y install libpcap libpcap-devel
sudo cp -rf bro /usr/local/
ldconfig