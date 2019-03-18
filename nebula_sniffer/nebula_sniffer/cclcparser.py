#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import json

from threathunter_common.event import Event
from threathunter_common.geo.ip import is_private_ip
from threathunter_common.util import millis_now

from .parserutil import extract_value_from_body, get_md5
from .parser import extract_common_properties, Parser, extract_http_log_event
from .msg import HttpMsg

__author__ = "nebula"

r"""
Login event extractor
"""
l_passwd_pattern = re.compile("(&|^)password=(.*?)($|&)")
l_name_pattern = re.compile("(&|^)mobile=(.*?)($|&)")


def extract_login_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if httpmsg.uri != "/member/login":
        return

    properties = extract_common_properties(httpmsg)
    if "err" in httpmsg.resp_body:
        result = "F"
    else:
        result = "T"
    properties["result"] = result

    body = httpmsg.req_body or ""

    properties["password"] = get_md5(get_md5(get_md5(get_md5(get_md5(
        extract_value_from_body(l_passwd_pattern, body))))))
    properties["login_name"] = extract_value_from_body(l_name_pattern, body)
    properties["login_type"] = "pc"
    properties["auth_msg"] = ""
    properties["autologin"] = False
    properties["captcha"] = ""

    return Event("nebula", "loginlog", "", millis_now(), properties)


#  ##############App Regist part##################
app_l_passwd_pattern = re.compile("(&|^)pwd=(.*?)($|&)")
app_l_name_pattern = re.compile("(&|^)mobile=(.*?)($|&)")


def extract_app_login_log_event(httpmsg):
    r"""
    App login event extractor
    """
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if httpmsg.uri != "/api/c1_login":
        return

    properties = extract_common_properties(httpmsg)
    result = "F"
    try:
        j = json.loads(httpmsg.resp_body)
        if j["err"] is None:
            result = "T"
    except:
        pass
    properties["result"] = result

    body = httpmsg.req_body or ""

    properties["password"] = get_md5(get_md5(get_md5(get_md5(get_md5(
        extract_value_from_body(app_l_passwd_pattern, body))))))
    properties["login_name"] = extract_value_from_body(app_l_name_pattern, body)
    properties["login_type"] = "pc"
    properties["auth_msg"] = ""
    properties["autologin"] = False
    properties["captcha"] = ""

    return Event("nebula", "loginlog", "", millis_now(), properties)


#  ##############Regist part##################
r_mobile_pattern = re.compile("(&|^)mobile=(.*?)($|&)")


def extract_regist_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if httpmsg.uri != "/member/register":
        return

    properties = extract_common_properties(httpmsg)
    if "err" in httpmsg.resp_body:
        result = "F"
    else:
        result = "T"
    properties["result"] = result

    body = httpmsg.req_body or ""

    properties["email"] = ""
    properties["regist_name"] = extract_value_from_body(r_mobile_pattern, body)
    properties["password"] = ""
    properties["captcha"] = ""
    return Event("nebula", "registlog", "", millis_now(), properties)


#  ##############app regist part##################
app_r_name_pattern = re.compile("(&|^)mobile=(.*?)($|&)")
app_r_password_pattern = re.compile("(&|^)pwd=(.*?)($|&)")


def extract_app_regist_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "/api/c1_register" not in httpmsg.uri:
        return

    properties = extract_common_properties(httpmsg)
    result = "F"
    try:
        j = json.loads(httpmsg.resp_body)
        if j["err"] is None:
            result = "T"
    except:
        pass
    properties["result"] = result

    body = httpmsg.req_body or ""

    properties["email"] = ""
    properties["regist_name"] = extract_value_from_body(app_r_name_pattern, body)
    properties["mobile"] = extract_value_from_body(app_r_name_pattern, body)
    properties["password"] = get_md5(get_md5(get_md5(get_md5(get_md5(
        extract_value_from_body(l_passwd_pattern, body))))))
    properties["captcha"] = ""
    return Event("nebula", "registlog", "", millis_now(), properties)


#  ############Parser############################
class CclcParser(Parser):

    def __init__(self):
        super(CclcParser, self).__init__()
        self.http_msg_parsers = [extract_http_log_event, extract_regist_log_event, extract_app_login_log_event,
                                 extract_app_regist_log_event]

    def name(self):
        return "cclc parser"

    def get_logbody_config(self):
        return ["member/login", "api/c1_login", "member/register", "api/c1_register"]

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
        return []

    def filter(self, msg):
        if not isinstance(msg, HttpMsg):
            return False

        if is_private_ip(msg.source_ip):
            return True

        return False


Parser.add_parser("cclc", CclcParser())
