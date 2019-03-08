#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re

from threathunter_common.util import text, millis_now
from threathunter_common.event import Event

from ..parser import Parser, extract_common_properties, extract_http_log_event
from ..parserutil import extract_value_from_body, get_md5, get_json_obj
from ..msg import HttpMsg
from ..cache import Cache

__author__ = 'lw'


def get_result(body):
    if body:
        try:
            body = get_json_obj(body)
        except Exception as err:
            raise RuntimeError("can't decode json", body)
        if body and body.get("Success", False):
            return True

    return False


def extract_app_login_log_event(httpmsg):
    """
    App Login event extractor
    """

    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "member/membershiphandler.ashx" not in httpmsg.uri:
        return

    properties = extract_common_properties(httpmsg)

    req_body = httpmsg.req_body or ""
    request = get_json_obj(req_body)
    resp_body = httpmsg.resp_body or ""
    response = get_json_obj(resp_body)

    if not request.get("request", {}).get("header", {}).get("serviceName", "").startswith("Loginv"):
        return

    properties["password"] = request.get("request", {}).get("body", {}).get("password", "")
    properties["login_name"] = request.get("request", {}).get("body", {}).get("loginName", "")
    response_header = response.get("response", {}).get("header", {})
    if response_header.get("rspType") == '0' and text(response_header.get('rspDesc', "")) == u'登录成功':
        login_result = "T"
    else:
        login_result = "F"
    properties["login_result"] = login_result
    properties["login_type"] = "password"
    properties["auth_msg"] = ""
    properties["autologin"] = False
    properties["captcha"] = ""
    properties["uid"] = response.get("response", {}).get("body", {}).get("memberId", "")
    properties["deviceid"] = request.get("request", {}).get("body", {}).get("clientInfo", {}).get("deviceId", "")

    return Event("nebula", "loginlog", "", millis_now(), properties)


l_passwd_pattern = re.compile("(&|^)Passwd=(.*?)($|&)")
l_name_pattern = re.compile("(&|^)LoginName=(.*?)($|&)")
l_captcha_pattern = re.compile("(&|^)ValidateCode=(.*?)($|&)")


def extract_login_log_event(httpmsg):
    """
    Login event extractor
    """

    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if httpmsg.uri != "/m/login.html":
        return

    properties = extract_common_properties(httpmsg)

    body = httpmsg.resp_body or ""
    result = get_result(body)
    properties["login_result"] = result

    properties["password"] = get_md5(extract_value_from_body(l_passwd_pattern, body))
    properties["login_name"] = extract_value_from_body(l_name_pattern, body)
    properties["login_type"] = "pc"
    properties["auth_msg"] = ""
    properties["autologin"] = False
    properties["captcha"] = extract_value_from_body(l_captcha_pattern, body)

    return Event("nebula", "loginlog", "", millis_now(), properties)


#  ##############Regist part##################
r_name_pattern = re.compile("(&|^)Mobile=(.*?)($|&)")
r_passwd_pattern = re.compile("(&|^)Passwd=(.*?)($|&)")
r_captcha_pattern = re.compile("(&|^)ValidateCode=(.*?)($|&)")
regist_cache = Cache(10000, ttl=600)


def extract_regist_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if httpmsg.uri not in {"/m/register.html", "/m/sendregistercode.html"}:
        return

    key = (httpmsg.source_ip, httpmsg.source_port, httpmsg.dest_ip, httpmsg.dest_port)
    regist_name = ""
    password = ""
    captcha = ""
    regist_result = "F"
    if httpmsg.uri == "/m/register.html":
        req_body = httpmsg.req_body or ""
        resp_body = httpmsg.resp_body or ""
        regist_name = extract_value_from_body(r_name_pattern, req_body)
        password = get_md5(extract_value_from_body(r_passwd_pattern, req_body))
        captcha = extract_value_from_body(r_captcha_pattern, req_body)
        result = get_result(resp_body)
        if result:
            # success, go to the cache, and return for further process
            regist_cache[key] = {"regist_name": regist_name, "password": password, "captcha": captcha}
            return
        else:
            regist_result = "F"
    else:
        # should be the third step
        resp_body = httpmsg.resp_body or ""
        result = get_result(resp_body)
        if result:
            regist_result = "T"
        else:
            regist_result = "F"
        data = regist_cache.get(key, {})
        if not data:
            regist_result = "F"
        regist_name = data.get("regist_name", "")
        password = data.get("password", "")
        captcha = data.get("captcha", "")

    properties = extract_common_properties(httpmsg)
    properties["regist_result"] = regist_result
    properties["email"] = ""
    properties["regist_name"] = regist_name
    properties["password"] = password
    properties["captcha"] = captcha
    return Event("nebula", "registlog", "", millis_now(), properties)


#  ##############password_modify##################
pwmodify_oldpwd_pattern = re.compile("(&|^)oldpassword=(.*?)($|&)")
pwmodify_newpwd_pattern = re.compile("($|^)newpassword=(.*?)($|&)")


def extract_password_modify_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if httpmsg.uri != '/m/updatepwd.html':
        return

    properties = extract_common_properties(httpmsg)

    body = httpmsg.resp_body or ""
    result = get_result(body)

    properties["result"] = result
    properties["old_password"] = get_md5(extract_value_from_body(pwmodify_oldpwd_pattern, httpmsg.req_body))
    properties["new_password"] = get_md5(extract_value_from_body(pwmodify_newpwd_pattern, httpmsg.req_body))

    return Event("nebula", "password_modify", httpmsg.source_ip, millis_now(), properties)


#  ##############password_reset##################
pwreset_mobile_pattern = re.compile("(&|^)phone=(.*?)($|&)")
pwreset_captcha_pattern = re.compile("(&|^)ValidateCode=(.*?)($|&)")
pwreset_auth_pattern = re.compile("(&|^)ValidateCode=(.*?)($|&)")
pwreset_newpw_pattern = re.compile("(&|^)Password=(.*?)($|&)")
reset_cache = Cache(10000, 600)


def extract_password_reset_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if httpmsg.uri not in {"/m/forgetpasswd.html", "/m/inputvalidatecode.html", "/m/updatepasswd.html"}:
        return

    key = (httpmsg.source_ip, httpmsg.source_port, httpmsg.dest_ip, httpmsg.dest_port)
    mobile = ""
    captcha = ""
    auth_msg = ""
    new_password = ""
    reset_result = "F"

    if httpmsg.uri == "/m/forgetpasswd.html":
        mobile = extract_value_from_body(pwreset_mobile_pattern, httpmsg.req_body)
        captcha = extract_value_from_body(pwreset_captcha_pattern, httpmsg.req_body)
        result = get_result(httpmsg.resp_body)
        if result:
            # success, go to the cache, and return for further process
            reset_cache[key] = {"mobile": mobile, "captcha": captcha}
            return
        else:
            reset_result = "F"
    elif httpmsg.uri == "/m/inputvalidatecode.html":
        auth_msg = extract_value_from_body(pwreset_auth_pattern, httpmsg.req_body)
        result = get_result(httpmsg.resp_body)
        data = reset_cache.get(key, {})
        if result and data:
            data["auth_msg"] = auth_msg
            return
        else:
            reset_result = "F"
            if data:
                mobile = data["mobile"]
                captcha = data["captcha"]
    else:
        # last step
        result = get_result(httpmsg.resp_body)
        data = reset_cache.get(key, {})
        if result:
            reset_result = "T"
        else:
            reset_result = "F"
        if data:
            mobile = data["mobile"]
            captcha = data["captcha"]
            auth_msg = data["auth_msg"]
        else:
            reset_result = "F"
        new_password = get_md5(extract_value_from_body(pwreset_newpw_pattern, httpmsg.req_body))

    properties = extract_common_properties(httpmsg)
    properties["result"] = reset_result
    properties["mobile"] = mobile
    properties["captcha"] = captcha
    properties["auth_msg"] = auth_msg
    properties["new_password"] = new_password
    properties["step"] = 3

    return Event("nebula", "password_reset", httpmsg.source_ip, millis_now(), properties)


#  ############Parser############################
class TCParser(Parser):

    def __init__(self):
        super(TCParser, self).__init__()
        self.http_msg_parsers = [extract_http_log_event, extract_regist_log_event, extract_login_log_event,
                                 extract_password_modify_log_event, extract_password_reset_log_event,
                                 extract_app_login_log_event]

    def name(self):
        return "Tongcheng customparsers"

    def get_logbody_config(self):
        return ["login", "register", "forgetpasswd", "inputvalidatecode", "inputvalidatecode", "updatepwd",
                "membershiphandler"]

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

        # if not msg.source_ip or msg.source_ip.startswith("172.16.") or msg.source_ip.startswith("192.168.") \
        #         or msg.source_ip.startswith("10."):
        #     return True

        return False


Parser.add_parser("tc", TCParser())
