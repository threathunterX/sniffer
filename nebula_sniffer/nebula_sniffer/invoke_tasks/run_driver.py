# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from __future__ import absolute_import

import sys
import logging
from os import path, symlink, chdir

from invoke import run, task, call

# 项目跟目录
BASE_DIR = path.realpath(
    path.join(path.dirname(path.realpath(__file__)), "../../"))

# http.bro默认 src/dst
DEFAULT_HTTP_BRO_SRC = path.join(BASE_DIR, "bro_scripts/http_main.bro")
DEFAULT_HTTP_BRO_DST = "/usr/local/bro/share/bro/base/protocols/http/main.bro"

# logging to stdout
logging.basicConfig(level=logging.INFO,
                    stream=sys.stdout)


@task
def rm_old_http_brp():
    u""" 删除http.bro """
    if path.exists(DEFAULT_HTTP_BRO_DST):
        run("sudo rm {}".format(DEFAULT_HTTP_BRO_DST))


@task(pre=[rm_old_http_brp])
def lnk_http_bro(src, dst):
    u""" 创建http.bro脚本link """
    # 只能支持绝对路径
    assert path.isabs(src) and path.isabs(dst), "link http.bro需要使用绝对路径"

    symlink(src, dst)


@task(pre=[call(lnk_http_bro, DEFAULT_HTTP_BRO_SRC, DEFAULT_HTTP_BRO_DST)])
def bro_server(bro_file, interface="eth0", bro_path="/usr/local/bro/bin/bro"):
    u""" 跑bro服务进程 """
    # 获取绝对路径
    bro_file = path.realpath(bro_file)
    http_file = "/usr/local/bro/share/bro/base/protocols/http/main.bro"
    bro_scripts = ' '.join([bro_file, http_file])

    cmd = "sudo {bro_path} -C -b -i {interface} {bro_scripts}"
    cmd = cmd.format(bro_path=bro_path,
                     interface=interface,
                     bro_scripts=bro_scripts)

    msg = "the cmd is: %s" % cmd
    logging.info(msg)

    # change pwd to /tmp
    tmp_dir = path.join(path.dirname(path.realpath(__file__)), '../../tmp/')
    chdir(tmp_dir)

    result = run(cmd)
    logging.info(result.__dict__)
