# -*- coding: utf-8 -*-

u"""
nebula_sniffer自动任务管理:

    * 自动部署开发环境
"""

from __future__ import unicode_literals
from __future__ import absolute_import

import sys
import logging

from invoke import run, task, Collection

from nebula_sniffer.invoke_tasks import generate, run_driver

# logging to stdout
logging.basicConfig(level=logging.INFO,
                    stream=sys.stdout)


@task
def install_bro():
    """安装bro抓包工具"""
    print "only support ubuntu now."
    # 安装libs
    run("sudo apt-get install cmake make gcc g++ flex bison"
        " libpcap-dev libssl-dev python-dev swig zlib1g-dev")

    # 下载解压bro.并安装
    run("wget -c https://www.bro.org/downloads/release/bro-2.4.1.tar.gz"
        " -O ~/Downloads/bro-2.4.1.tar.gz")
    run("cd ~/Downloads && tar xvaf bro-2.4.1.tar.gz")
    run("cd ~/Downloads/bro-2.4.1 && ./configure && make && sudo make install")
    print "remember to set bro to your path!"


@task
def install_broccoli_python():
    """安装bro client python绑定"""
    print "only support ubuntu now."
    # 下载解压
    run("wget -O ~/Downloads/broccoli-python-0.59.tar.gz -c "
        "https://www.bro.org/downloads/release/broccoli-python-0.59.tar.gz")
    run("cd ~/Downloads && tar xvaf broccoli-python-0.59.tar.gz")

    # 安装
    run("cd ~/Downloads/broccoli-python-0.59/"
        " && export PATH=/usr/local/bro/bin:${PATH} "
        " && export LD_LIBRARY_PATH=/usr/local/bro/lib:${LD_LIBRARY_PATH} "
        " && ./configure && make && python setup.py install")

    run('echo "export PATH=/usr/local/bro/bin:${PATH}" >> ~/.bashrc')


@task(pre=[install_bro, install_broccoli_python])
def make_dev():
    """ 自动完成开发环境部署 """
    run("sudo apt-get install redis-server")
    run("pip install -r requirements.txt")


# 管理invoke命名空间
ns = Collection()
ns.add_task(make_dev)
ns.add_task(install_bro)
ns.add_task(install_broccoli_python)

gen = Collection("gen")
gen.add_task(generate.bro)
ns.add_collection(gen)

run_ns = Collection("run")
run_ns.add_task(run_driver.bro_server)
ns.add_collection(run_ns, name="run")
