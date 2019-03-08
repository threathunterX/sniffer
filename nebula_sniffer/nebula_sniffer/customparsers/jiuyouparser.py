#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re

from threathunter_common.util import millis_now
from threathunter_common.event import Event

from ..parser import Parser, extract_common_properties, extract_http_log_event
from ..parserutil import extract_value_from_body, get_json_obj, get_md5
from ..msg import HttpMsg


def get_result(body):
    if body:
        try:
            body = get_json_obj(body)
        except Exception as err:
            raise RuntimeError("can't decode json", body)
        if body and body.get("Success", False):
            return True

    return False


l_passwd_pattern = re.compile("(&|^)password=(.*?)($|&)")
l_name_pattern = re.compile("(&|^)userName=(.*?)($|&)")
l_captcha_pattern = re.compile("(&|^)identifyingCode=(.*?)($|&)")


def extract_login_log_event(httpmsg):
    """
    Login event extractor
    """

    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "/checkcode" not in httpmsg.uri:
        return

    properties = extract_common_properties(httpmsg)

    body = httpmsg.req_body or ""
    result = "F"
    if httpmsg.status_code == 302 and '''The URL has moved <a href="http://login.passport.9you.com/loginloading.jsp''' \
            in httpmsg.resp_body:
        result = "T"
    properties["login_result"] = result
    properties["password"] = get_md5(extract_value_from_body(l_passwd_pattern, body))
    properties["login_name"] = extract_value_from_body(l_name_pattern, body)
    properties["login_type"] = "pc"
    properties["auth_msg"] = ""
    properties["autologin"] = False
    properties["captcha"] = extract_value_from_body(l_captcha_pattern, body)

    return Event("nebula", "loginlog", "", millis_now(), properties)


#  ############Parser############################
class JiuUParser(Parser):

    def __init__(self):
        super(JiuUParser, self).__init__()
        self.http_msg_parsers = [extract_http_log_event, extract_login_log_event]

    def name(self):
        return "9u customparsers"

    def get_logbody_config(self):
        return ["checkcode"]

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


Parser.add_parser("9u", JiuUParser())
