#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
from .parser import *
from .parserutil import *
from threathunter_common.event import Event

__author__ = "nebula"

l_passwd_pattern = re.compile("(&|^)password=(.*?)($|&)")
l_name_pattern = re.compile("(&|^)username=(.*?)($|&)")
l_captcha_pattern = re.compile("(&|^)vcode=(.*?)($|&)")


def extract_login_log_event(httpmsg):
    r"""
    Login event extractor
    """

    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    print httpmsg
    if "/flow/dispatch_post.do" not in httpmsg.uri:
        return
    if "action=submitLogin" not in httpmsg.req_body:
        return

    properties = extract_common_properties(httpmsg)
    location = httpmsg.resp_headers.get("LOCATION", "")
    print 333, location
    result = "F"
    if r"\u767b\u9646\u6210\u529f" in location:
        result = "T"
    properties["result"] = result

    body = httpmsg.req_body or ""

    properties["password"] = get_md5(get_md5(get_md5(get_md5(get_md5(
        extract_value_from_body(l_passwd_pattern, body))))))
    properties["login_name"] = extract_value_from_body(l_name_pattern, body)
    properties["login_type"] = "pc"
    properties["auth_msg"] = ""
    properties["autologin"] = False
    properties["captcha"] = extract_value_from_body(l_captcha_pattern, body)

    return Event("nebula", "loginlog", "", millis_now(), properties)


#  ##############Regist part##################
r_name_pattern = re.compile("(&|^)mobilePhone=(.*?)($|&)")
r_passwd_pattern = re.compile("(&|^)password=(.*?)($|&)")
r_captcha_pattern = re.compile("(&|^)vcode=(.*?)($|&)")
r_channel_pattern = re.compile("(&|^)channelCode=(.*?)($|&)")
r_invitemobile_pattern = re.compile("(&|^)inviteMobilePhone=(.*?)($|&)")


def extract_regist_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "/flow/dispatch_post.do" not in httpmsg.uri:
        return
    if "action=doRegisterUser" not in httpmsg.req_body:
        return

    properties = extract_common_properties(httpmsg)
    result = "F"
    location = httpmsg.resp_headers.get('LOCATION', '')
    print 333, location
    if r'\u606d\u559c\u60a8\u6ce8\u518c\u6210\u529f\u002c\u8bf7\u5b8c\u6210\u5b9e\u540d\u8ba4\u8bc1\u0021' in location:
        result = "T"
    properties["result"] = result

    body = httpmsg.req_body or ""

    properties["email"] = ""
    properties["regist_name"] = extract_value_from_body(r_name_pattern, body)
    properties["mobile"] = extract_value_from_body(r_name_pattern, body)
    properties["password"] = get_md5(get_md5(get_md5(get_md5(get_md5(
        extract_value_from_body(r_passwd_pattern, body))))))
    properties["captcha"] = extract_value_from_body(r_captcha_pattern, body)

    if "m.duc365" in httpmsg.host:
        properties["channel"] = extract_value_from_body(r_channel_pattern, body)
        properties["invite_mobile"] = extract_value_from_body(r_invitemobile_pattern, body)
    else:
        properties["channel"] = ""
        properties["invite_mobile"] = ""

    return Event("nebula", "registlog", "", millis_now(), properties)


#  ##############App Regist part##################
app_l_passwd_pattern = re.compile("(&|^)password=(.*?)($|&)")
app_l_name_pattern = re.compile("(&|^)username=(.*?)($|&)")
app_l_captcha_pattern = re.compile("(&|^)vcode=(.*?)($|&)")


def extract_app_login_log_event(httpmsg):
    r"""
    app login event extractor
    """

    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "/user/loginuser" not in httpmsg.uri:
        return

    properties = extract_common_properties(httpmsg)
    result = "F"
    try:
        j = json.loads(httpmsg.resp_body)
        if j["retCode"] == 1:
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
app_r_name_pattern = re.compile("(&|^)mobilePhone=(.*?)($|&)")
app_r_passwd_pattern = re.compile("(&|^)password=(.*?)($|&)")


def extract_app_regist_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "/user/registeruser" not in httpmsg.uri:
        return

    properties = extract_common_properties(httpmsg)
    result = "F"
    try:
        j = json.loads(httpmsg.resp_body)
        if j["retCode"] == 1:
            result = "T"
    except:
        pass
    properties["result"] = result

    body = httpmsg.req_body or ""

    properties["email"] = ""
    properties["regist_name"] = extract_value_from_body(app_r_name_pattern, body)
    properties["mobile"] = extract_value_from_body(app_r_name_pattern, body)
    properties["password"] = get_md5(get_md5(get_md5(get_md5(get_md5(
        extract_value_from_body(app_r_passwd_pattern, body))))))
    properties["captcha"] = ""
    return Event("nebula", "registlog", "", millis_now(), properties)


#  ##############bank card bind part##################
bcb_card_no_pattern = re.compile("(&|^)cardNo=(.*?)($|&)")


def extract_bank_card_bind_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "web/auth/post" not in httpmsg.uri:
        return

    properties = extract_common_properties(httpmsg)
    result = "F"
    try:
        j = json.loads(httpmsg.resp_body)
        if j["retCode"] == 1:
            result = "T"
    except:
        pass
    properties["result"] = result

    body = httpmsg.req_body or ""

    properties["card_no"] = extract_value_from_body(bcb_card_no_pattern, body)
    return Event("nebula", "bank_card_bind", "", millis_now(), properties)


#  ##############identity verify part ##################
iv_name_pattern = re.compile("(&|^)personName=(.*?)($|&)")
iv_id_pattern = re.compile("(&|^)personCardNo=(.*?)($|&)")


def extract_identity_verify_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "/flow/dispatch_post.do" not in httpmsg.uri:
        return
    if "action=submitRealNameAuth" not in httpmsg.req_body:
        return

    properties = extract_common_properties(httpmsg)
    result = "F"
    location = httpmsg.resp_headers.get('LOCATION', '')
    print 333, location
    if r'\u8eab\u4efd\u5b9e\u540d\u8ba4\u8bc1\u6210\u529f' in location:
        result = "T"
    properties["result"] = result

    body = httpmsg.req_body or ""

    properties["name"] = extract_value_from_body(iv_name_pattern, body)
    properties["id"] = extract_value_from_body(iv_id_pattern, body)

    return Event("nebula", "identity_verify", "", millis_now(), properties)


#  ############Parser############################
class DingyoucaiParser(Parser):

    def __init__(self):
        super(DingyoucaiParser, self).__init__()
        self.http_msg_parsers = [extract_http_log_event, extract_regist_log_event, extract_login_log_event,
                                 extract_app_login_log_event, extract_app_regist_log_event,
                                 extract_identity_verify_log_event, extract_bank_card_bind_log_event]

    def name(self):
        return "dingyoucai parser"

    def get_logbody_config(self):
        return ["dispatch_post.do", "loginuser", "registeruser"]

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


Parser.add_parser("dingyoucai", DingyoucaiParser())
