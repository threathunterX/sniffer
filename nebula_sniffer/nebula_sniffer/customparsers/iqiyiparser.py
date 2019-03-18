#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import datetime

from threathunter_common.event import Event
from threathunter_common.util import millis_now

from ..parser import Parser
from ..msg import TextMsg

__author__ = "nebula"


def get_full_uri(host, port, path):
    result = host
    if port != 80:
        result = result + ":" + str(port)
    result += path
    return result


pattern = re.compile("(.?)*( |\")")


def extract_nginx_log_parts(part):
    if not part:
        return []

    part = part.strip()
    result = []

    while part:
        if part.startswith('"'):
            end = part.find('" ', 1)
            if end >= 1:
                result.append(part[1:end])
                part = part[end + 2:]
                continue
            else:
                raise RuntimeError("invalid log")
        elif part.startswith('['):
            end = part.find('] ', 1)
            if end >= 1:
                result.append(part[1:end])
                part = part[end + 2:]
                continue
            else:
                raise RuntimeError("invalid log")
        else:
            end = part.find(" ", 1)
            if end >= 1:
                result.append(part[:end])
                part = part[end + 1:]
                continue
            else:
                result.append(part)
                break
    result = [None if _ == "-" else _ for _ in result]
    return result


def extract_http_log_msg(textmsg):
    if not textmsg:
        return None

    server_ip, remote_ip, status, request_time, upstream_response_time, log = textmsg.split("|||")
    parts = extract_nginx_log_parts(log)
    if len(parts) != 14:
        raise RuntimeError("invalid log")

    user_agent = parts[8] or ""
    method, uri = parts[4].split(" ")[:2]

    # get full uri
    if "?" not in uri:
        uri_stem = uri
        uri_query = ""
    else:
        uri_stem, uri_query = uri.split("?", 1)

    properties = dict()
    properties["c_ip"] = remote_ip
    properties["c_ipc"] = ".".join(remote_ip.split(".")[:3])
    properties["c_port"] = 0
    properties["uri_stem"] = uri_stem
    properties["uri_query"] = uri_query
    properties["host"] = ""
    properties["useragent"] = user_agent
    properties["status"] = int(status)
    properties["referer"] = ""
    properties["c_body"] = ""
    properties["c_bytes"] = int(parts[10])
    properties["s_ip"] = server_ip
    properties["s_ipc"] = ".".join(server_ip.split(".")[:3])
    properties["s_port"] = 0
    properties["s_body"] = ""
    properties["s_bytes"] = int(parts[6])
    properties["cookie"] = ""
    properties["method"] = method
    # print properties
    return Event("nebula", "httplog", "", millis_now(), properties)


#  ############Parser############################
class IqiyiParser(Parser):

    def __init__(self):
        pass

    def name(self):
        return "iqiyi customparsers"

    def get_logbody_config(self):
        return []

    def get_events_from_http_msg(self, http_msg):
        return []

    def get_events_from_text_msg(self, text_msg):
        return []

    def filter(self, msg):
        if not isinstance(msg, TextMsg):
            return True


Parser.add_parser("iqiyi", IqiyiParser())
