#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re

from threathunter_common.util import millis_now
from threathunter_common.event import Event

from ..parser import Parser, extract_common_properties, extract_http_log_event
from ..parserutil import extract_value_from_body, get_json_obj, get_md5
from ..msg import HttpMsg

__author__ = 'lw'

"""
Login event extractor
"""
l_passwd_pattern = re.compile("(&|^)password=(.*?)($|&)")
l_name_pattern = re.compile("(&|^)username=(.*?)($|&)")


def extract_login_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "/pc/login/member.action" not in httpmsg.uri:
        return

    properties = extract_common_properties(httpmsg)

    result = "F"
    uid = ""
    body = httpmsg.resp_body or ""
    if body:
        try:
            body = get_json_obj(body)
            code = body["code"]
            if code == 1000:
                result = "T"
                uid = str(body["msg"]["uid"])
            elif code == 1038:
                result = "N"
            elif code == 1039:
                result = "F"

        except Exception as err:
            pass

    properties["login_result"] = result

    properties["password"] = get_md5(extract_value_from_body(l_passwd_pattern, httpmsg.req_body))
    properties["login_name"] = extract_value_from_body(l_name_pattern, httpmsg.req_body)
    properties["login_type"] = "pc"
    properties["auth_msg"] = ""
    properties["autologin"] = False
    properties["captcha"] = ""
    properties["uid"] = uid
    properties["deviceid"] = ""

    return Event("nebula", "loginlog", "", millis_now(), properties)


#  ##############Regist part##################
r_mobile_pattern = re.compile("(&|^)mobile=(.*?)($|&)")


def extract_regist_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "pc/mobileregister.action" not in httpmsg.uri:
        return

    result = "F"
    body = httpmsg.resp_body or ""
    if body:
        try:
            body = get_json_obj(body)
            code = body["code"]
            if code == 1000:
                result = "T"

        except Exception as err:
            pass

    properties = extract_common_properties(httpmsg)
    properties["regist_result"] = result
    properties["email"] = ""
    properties["regist_name"] = extract_value_from_body(r_mobile_pattern, body)
    properties["password"] = ""
    properties["captcha"] = ""
    return Event("nebula", "registlog", "", millis_now(), properties)


#  ##############password_reset##################
pwreset_mobile_pattern = re.compile("(&|^)mobile=(.*?)($|&)")
pwreset_email_pattern = re.compile("(&|^)email=(.*?)($|&)")
pwreset_mode_pattern = re.compile("(&|^)mode=(.*?)($|&)")
pwreset_username_pattern = re.compile("(&|^)username=(.*?)($|&)")
pwreset_auth_pattern = re.compile("(&|^)authcode=(.*?)($|&)")

pwreset_newpw_pattern = re.compile("(&|^)Password=(.*?)($|&)")
pwreset_captcha_pattern = re.compile("(&|^)ValidateCode=(.*?)($|&)")


def extract_password_reset_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "ucenter/checkpwdmender.action" not in httpmsg.uri:
        return

    mode = extract_value_from_body(pwreset_mode_pattern, httpmsg.req_body)
    token = ""
    step = ""
    if mode == "mobile":
        token = extract_value_from_body(pwreset_mobile_pattern, httpmsg.req_body)
        step = "手机找回密码"
    elif mode == "email":
        token = extract_value_from_body(pwreset_email_pattern, httpmsg.req_body)
        step = "邮箱找回密码"

    result = "F"
    body = httpmsg.resp_body or ""
    if body:
        try:
            body = get_json_obj(body)
            code = body["code"]
            if code == 1000:
                result = "T"

        except Exception as err:
            pass

    properties = extract_common_properties(httpmsg)
    properties["result"] = result
    properties["mobile"] = ""
    properties["token"] = token
    properties["username"] = extract_value_from_body(pwreset_username_pattern, httpmsg.req_body)
    properties["captcha"] = ""
    properties["auth_msg"] = ""
    if mode == "mobile":
        properties["auth_msg"] = extract_value_from_body(pwreset_auth_pattern, httpmsg.req_body)
    properties["new_password"] = ""
    properties["step"] = step

    return Event("nebula", "password_reset", httpmsg.source_ip, millis_now(), properties)


#  ##############password_modify##################
pwmodify_oldpwd_pattern = re.compile("(&|^)password=(.*?)($|&)")
pwmodify_newpwd_pattern = re.compile("($|^)newPassword=(.*?)($|&)")
pwmodify_username_pattern = re.compile("($|^)value=(.*?)($|&)")


def extract_password_modify_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if 'ucenter/repassword.action' not in httpmsg.uri:
        return

    properties = extract_common_properties(httpmsg)

    result = "F"
    body = httpmsg.resp_body or ""
    if body:
        try:
            body = get_json_obj(body)
            code = body["code"]
            if code == 1000:
                result = "T"

        except Exception as err:
            pass

    properties["result"] = result
    properties["old_password"] = get_md5(extract_value_from_body(pwmodify_oldpwd_pattern, httpmsg.req_body))
    properties["new_password"] = get_md5(extract_value_from_body(pwmodify_newpwd_pattern, httpmsg.req_body))
    properties["username"] = extract_value_from_body(pwmodify_username_pattern, httpmsg.req_body)

    return Event("nebula", "password_modify", httpmsg.source_ip, millis_now(), properties)


#  ##############password_reset##################

#  ############Parser############################
class HupuParser(Parser):

    def __init__(self):
        super(HupuParser, self).__init__()
        self.http_msg_parsers = [extract_http_log_event, extract_regist_log_event, extract_login_log_event,
                                 extract_password_modify_log_event, extract_password_reset_log_event]

    def name(self):
        return "hupu customparsers"

    def get_logbody_config(self):
        return ["login", "mobileregister", "ucenter/repassword", "ucenter/checkpwdmender"]

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

        if not msg.source_ip or msg.source_ip.startswith("172.16.") or msg.source_ip.startswith("192.168.") \
                or msg.source_ip.startswith("10."):
            return True

        return False


Parser.add_parser("hupu", HupuParser())
