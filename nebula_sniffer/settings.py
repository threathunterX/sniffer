# -*- coding: utf-8 -*-

import os
from os import path as opath

# debug 模式

DEBUG = >DEBUG<

# path
Base_Path = opath.dirname(__file__)

# build conf path
Conf_Local_Path = opath.join(Base_Path, "conf")
Conf_Global_Path = "/etc/nebula"
Conf_Sniffer_Path = "/etc/nebula/sniffer"
if not os.path.exists(Conf_Global_Path) or not os.path.isdir(Conf_Global_Path):
    print "global conf path using the local path {}".format(Conf_Local_Path)
    Conf_Global_Path = Conf_Local_Path
if not os.path.exists(Conf_Sniffer_Path) or not os.path.isdir(Conf_Sniffer_Path):
    print "sniffer conf path using the local path {}".format(Conf_Local_Path)
    Conf_Sniffer_Path = Conf_Local_Path

# build log path
Log_Local_Path = opath.join(Base_Path, "logs")
Log_Path = "/data/logs/sniffer"
if not os.path.exists(Log_Path) or not os.path.isdir(Log_Path):
    Log_Path = Log_Local_Path

# log配置
# Logging_Conf = opath.join(Base_Path, "logging.conf")
Logging_File = opath.join(Log_Path, 'sniffer.log')
Logging_Format = "%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
Logging_Datefmt = '%Y-%m-%d %H:%M:%S'

Sniffer_Conf_FN = opath.join(Conf_Sniffer_Path, 'sniffer.conf')
Sniffer_Conf_Tem = opath.join(Conf_Sniffer_Path, 'sniffer.conf.tem')

Global_Conf_FN = opath.join("/etc/nebula", "nebula.conf")

Sniffer_Version = '1.0.0'

Interfaces = ['eth0', 'eth1']

Drivers = ['bro', 'tshark', 'syslog', 'kafka']

Babel_Service_Mode = 'redis'


def init_logging(name):
    print('creat logger {}'.format(name))
    import logging.config
    log = logging.getLogger(name)
    if DEBUG:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    log.setLevel(log_level)
    handler = logging.handlers.TimedRotatingFileHandler(os.path.join(Log_Path, name + '.log'), when='D', interval=1,
                                                        backupCount=7)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"))
    log.addHandler(handler)
    return log
