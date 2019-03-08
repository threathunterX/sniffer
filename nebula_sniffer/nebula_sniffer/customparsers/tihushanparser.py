#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import json
from threathunter_common.event import Event
from threathunter_common.util import millis_now

from ..parser import Parser, extract_common_properties, extract_http_log_event
from ..parserutil import extract_value_from_body, get_md5
from ..msg import HttpMsg


def extract_login_log_event(httpmsg):
    r"""
    Login event extractor
    """

    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "auth-web/authorize" not in httpmsg.uri:
        return

    properties = extract_common_properties(httpmsg)
    result = "F"
    body = httpmsg.resp_body
    try:
        body = json.loads(body)
        if body.get("msg_code") == "0":
            result = "T"
    except:
        pass
    properties["result"] = result

    body = httpmsg.req_body or ""
    password = ""
    user = ""
    try:
        body = json.loads(body)
        password = body["password"]
        user = body["user_acct"]
    except:
        pass

    properties["password"] = get_md5(password)
    properties["login_name"] = user
    properties["login_type"] = "pc"
    properties["auth_msg"] = ""
    properties["autologin"] = False
    properties["captcha"] = ""

    return Event("nebula", "loginlog", "", millis_now(), properties)


#  ##############Regist part##################
r_name_pattern = re.compile("(&|^)mobile_phone=(.*?)($|&)")
r_passwd_pattern = re.compile("(&|^)login_pwd=(.*?)($|&)")


def extract_regist_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "api/user/reg_user" not in httpmsg.uri:
        return

    properties = extract_common_properties(httpmsg)
    result = "F"
    body = httpmsg.resp_body
    try:
        body = json.loads(body)
        if body.get("msg_code") == "0":
            result = "T"
    except:
        pass
    properties["result"] = result

    body = httpmsg.req_body or ""
    password = ""
    user = ""
    try:
        body = json.loads(body)
        password = body["reg_user"]["login_pwd"]
        user = body["reg_user"]["mobile_phone"]
    except:
        pass

    properties["email"] = ""
    properties["regist_name"] = user
    properties["mobile"] = user
    properties["user"] = user
    properties["password"] = get_md5(password)
    properties["captcha"] = ""
    return Event("nebula", "registlog", "", millis_now(), properties)


#  ##############auth send msg part##################
a_name_pattern = re.compile("(&|^)mobile_phone=(.*?)($|&)")


def extract_auth_msg_send_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "GET":
        return
    if "api/sms/send_sms" not in httpmsg.uri:
        return

    properties = extract_common_properties(httpmsg)
    result = "T"
    properties["result"] = result

    properties["mobile"] = extract_value_from_body(a_name_pattern, httpmsg.uri_query)
    return Event("nebula", "auth_msg_send", "", millis_now(), properties)


#  ##############pay submit msg part##################


def extract_pay_submit_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "services/order/buy.json" not in httpmsg.uri:
        return

    properties = extract_common_properties(httpmsg)
    body = httpmsg.resp_body
    result = ""
    try:
        body = json.loads(body)
        if body.get("msg_code") == "0":
            result = "T"
    except:
        pass
    properties["result"] = result

    body = httpmsg.req_body or ""
    pay_type = ""
    pay_id = ""
    amount = ""
    mobile = ""
    try:
        body = json.loads(body)
        pay_type = body["data"]["s_type"]
        pay_id = body["data"]["lot_id"]
        amount = float(body["data"]["total_money"])
        mobile = body["token"]
    except:
        pass

    properties["pay_type"] = pay_type
    properties["pay_id"] = pay_id
    properties["amount"] = amount
    properties["mobile"] = mobile
    return Event("nebula", "pay_submit", "", millis_now(), properties)


#  ############Parser############################
class TihushanParser(Parser):

    def __init__(self):
        super(TihushanParser, self).__init__()
        self.http_msg_parsers = [extract_http_log_event, extract_regist_log_event, extract_login_log_event,
                                 extract_auth_msg_send_log_event, extract_pay_submit_log_event]

    def name(self):
        return "tihushan parser"

    def get_logbody_config(self):
        return []

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

        return False


Parser.add_parser("tihushan", TihushanParser())
