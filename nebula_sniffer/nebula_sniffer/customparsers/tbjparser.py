#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import json

from threathunter_common.geo.ip import is_private_ip
from threathunter_common.event import Event
from threathunter_common.util import millis_now

from ..parser import Parser, extract_common_properties, extract_http_log_event
from ..parserutil import extract_value_from_body, get_md5
from ..msg import HttpMsg

__author__ = "nebula"

#  ##############auth send msg part##################
a_name_pattern = re.compile("(&|^)phone=(.*?)($|&)")


def extract_auth_msg_send_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if httpmsg.uri != "web/sendsmscode":
        return

    properties = extract_common_properties(httpmsg)
    result = "F"
    resp_body = httpmsg.resp_body or ""
    try:
        b = json.loads(resp_body)
        if b.get("status") == 0:
            result = "T"
    except Exception as ignore:
        pass
    properties["result"] = result

    body = httpmsg.req_body or ""
    properties["mobile"] = extract_value_from_body(a_name_pattern, body)
    return Event("nebula", "auth_msg_send", "", millis_now(), properties)


#  ##############Regist part##################
r_name_pattern = re.compile("(&|^)phone=(.*?)($|&)")
r_passwd_pattern = re.compile("(&|^)password=(.*?)($|&)")
r_verify_pattern = re.compile("(&|^)verifiCode=(.*?)($|&)")


def extract_regist_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if httpmsg.uri != "/web/checkregister":
        return

    properties = extract_common_properties(httpmsg)
    result = "F"
    resp_body = httpmsg.resp_body or ""
    try:
        b = json.loads(resp_body)
        if b.get("status") == 0:
            result = "T"
    except Exception as ignore:
        pass
    properties["regist_result"] = result

    body = httpmsg.req_body or ""

    properties["email"] = ""
    properties["regist_name"] = extract_value_from_body(r_name_pattern, body)
    properties["mobile"] = extract_value_from_body(r_name_pattern, body)
    properties["password"] = get_md5(get_md5(get_md5(get_md5(get_md5(
        extract_value_from_body(r_passwd_pattern, body))))))
    properties["captcha"] = ""
    properties["auth_code"] = get_md5(get_md5(get_md5(get_md5(get_md5(
        extract_value_from_body(r_verify_pattern, body))))))
    return Event("nebula", "registlog", "", millis_now(), properties)


#  ##############order_submit##################
ordersubmit_sku_pattern = re.compile("(&|^)productId=(.*?)($|&)")
ordersubmit_cname_pattern = re.compile("(&|^)bankCardId=(.*?)($|&)")
ordersubmit_amount_pattern = re.compile("(&|^)amount=(.*?)($|&)")


def extract_order_submit_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "member/factoring/buy" not in httpmsg.uri_stem:
        return

    properties = extract_common_properties(httpmsg)

    result = "F"
    resp_body = httpmsg.resp_body or ""
    try:
        b = json.loads(resp_body)
        if b.get("status") == 0:
            result = "T"
    except Exception as ignore:
        pass
    properties["result"] = result
    properties["merchant"] = ""
    properties["orderid"] = ""
    properties["spu"] = ""
    properties["sku"] = extract_value_from_body(ordersubmit_sku_pattern, httpmsg.req_body)
    properties["sku_count"] = 0
    properties["reservation_time"] = millis_now()
    properties["c_name"] = get_md5(get_md5(get_md5(get_md5(get_md5(extract_value_from_body(ordersubmit_cname_pattern,
                                                                                           httpmsg.req_body))))))
    properties["email"] = ""
    properties["mobile"] = ""
    properties["order_amount"] = int(extract_value_from_body(ordersubmit_sku_pattern, httpmsg.req_body))
    return Event("nebula", "order_submit", httpmsg.source_ip, millis_now(), properties)


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
            elif part.endswith("\"") and len(part) > 1:
                result.append(part[1:end])
                break
            else:
                raise RuntimeError("invalid log:\"")
        elif part.startswith('['):
            end = part.find('] ', 1)
            if end >= 1:
                result.append(part[1:end])
                part = part[end + 2:]
                continue
            elif part.endswith("]") and len(part) > 1:
                result.append(part[1:end])
                break
            else:
                raise RuntimeError("invalid log: ]")
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


def extract_http_log_text_msg(textmsg):
    if not textmsg:
        return None

    t = textmsg.text
    j = json.loads(t)
    m = j["message"]
    remote_ip, _, _, _, _, log = m.split(" ", 5)
    parts = extract_nginx_log_parts(log)

    user_agent = parts[5] or ""
    referer = parts[4] or ""
    method, uri = parts[0].split(" ")[:2]
    uri = uri.lower()

    if parts[2]:
        status = int(parts[2])
    else:
        status = 0
    host = parts[1]

    if parts[7]:
        server_ip, server_port = parts[7].split(":")
    else:
        server_ip, server_port = "", "0"

    if parts[3]:
        s_bytes = int(parts[3])
    else:
        s_bytes = 0

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
    properties["host"] = host
    properties["useragent"] = user_agent
    properties["status"] = status
    properties["referer"] = referer
    properties["c_body"] = ""
    properties["c_bytes"] = 0
    properties["s_ip"] = server_ip
    properties["s_ipc"] = ".".join(server_ip.split(".")[:3])
    properties["s_port"] = int(server_port)
    properties["s_body"] = ""
    properties["s_bytes"] = s_bytes
    properties["cookie"] = ""
    properties["method"] = method

    return Event("nebula", "httplog", "", millis_now(), properties)


#  ############Parser############################
class TBJParser(Parser):

    def __init__(self):
        super(TBJParser, self).__init__()
        self.http_msg_parsers = [extract_http_log_event, extract_regist_log_event, extract_order_submit_log_event,
                                 extract_auth_msg_send_log_event]

    def name(self):
        return "tongbanjie customparsers"

    def get_logbody_config(self):
        return ["member/factoring/buy", "checkregister", "sendsmscode"]

    def get_events_from_http_msg(self, http_msg):
        if not http_msg:
            return []

        result = list()
        for p in self.http_msg_parsers:
            ev = p(http_msg)
            if ev:
                result.append(ev)
        return result

    def get_events_from_text_msg(self, text_msg):
        if not text_msg:
            return []

        result = list()
        ev = extract_http_log_text_msg(text_msg)
        if ev:
            result.append(ev)
        return result

    def filter(self, msg):
        if not isinstance(msg, HttpMsg):
            return False

        if is_private_ip(msg.source_ip):
            return True

        return False


Parser.add_parser("tbj", TBJParser())
