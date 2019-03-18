#!/usr/bin/env python
# -*- coding: utf-8 -*-
from babel_python.serviceclient_async import ServiceClient
from babel_python.servicemeta import ServiceMeta

__author__ = "nebula"


def get_httplog_rpc_client(amqp_url):
    http_service = """
    {
    "name": "httplog_notify",
    "callmode": "notify",
    "delivermode": "sharding",
    "serverimpl": "rabbitmq",
    "coder": "mail",
    "options": {
        "servercardinality": 2
    }
    }
    """

    client = ServiceClient(ServiceMeta.from_json(http_service), amqp_url=amqp_url)
    return client


def get_misclog_rpc_client(amqp_url):
    misc_service = """
    {
    "name": "misclog_notify",
    "callmode": "notify",
    "delivermode": "topic",
    "serverimpl": "rabbitmq",
    "coder": "mail",
    "options": {
    }
    }
    """

    client = ServiceClient(ServiceMeta.from_json(misc_service), amqp_url=amqp_url)
    return client
