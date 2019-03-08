#!/usr/bin/env python
# -*- coding: utf-8 -*-
from babel_python.serviceclient_async import ServiceClient
from babel_python.servicemeta import ServiceMeta
import os
from settings import Conf_Sniffer_Path

__author__ = 'lw'


def get_babel_file_content(filename):
    filepath = os.path.join(Conf_Sniffer_Path, 'babels', filename)
    if not os.path.exists(filepath):
        raise RuntimeError('babel配置文件{}不存在'.format(filename))

    with file(filepath) as file_obj:
        return file_obj.read()


def get_httplog_rpc_client():
    http_service = get_babel_file_content('Httplog_redis.service')

    client = ServiceClient(ServiceMeta.from_json(http_service))
    return client


def get_misclog_rpc_client():
    misc_service = get_babel_file_content('Misclog_redis.service')

    client = ServiceClient(ServiceMeta.from_json(misc_service))
    return client
