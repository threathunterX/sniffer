# -*- coding: utf-8 -*-

import logging
from os import path

import jinja2
from invoke import task

# 项目根目录
BASE_DIR = path.dirname(path.dirname(path.dirname(path.realpath(__file__))))
# 模板所在目录
TEMPLATE_DIR = path.join(BASE_DIR, "nebula_sniffer/templates")


def jinja2_render(template_name, **context):
    u"""
    jinja2渲染帮助函数
    @param template_name: 目录相对路径(相对与templates)
    @param **context 模板变量
    """

    loader = jinja2.FileSystemLoader(TEMPLATE_DIR)
    env = jinja2.Environment(loader=loader)
    template = env.get_template(template_name)

    return template.render(**context)


@task
def bro(port, name="script.bro", debug=False):
    u"""
    生成bro脚本文件
    @param port 监听端口
    @param name 生产的文件名
    @param debug True 输出到sysout
    """

    template_fn = "bro_scripts/script.bro.templ"
    msg = "template dir: {}".format(template_fn)
    logging.debug(msg)

    content = jinja2_render(template_fn, port=port)
    if isinstance(content, unicode):
        content = content.encode('utf8')

    if debug:
        print content
        return

    dst_dir = path.join(BASE_DIR, "bro_scripts")
    dst_fn = path.join(dst_dir, name)
    with open(dst_fn, 'w') as fp:
        fp.write(content)
        fp.flush()
