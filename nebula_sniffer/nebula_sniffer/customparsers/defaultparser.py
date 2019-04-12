#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import os
import logging
import subprocess
import json
from threathunter_common.util import millis_now
from threathunter_common.event import Event

from ..parser import Parser, extract_common_properties, extract_http_log_event
from ..parserutil import extract_value_from_body, get_md5, get_json_obj
from ..msg import HttpMsg
import time
import importlib
import settings
logger = settings.init_logging("sniffer.parser.{}".format("defaultparser"))


"""
#demo

#Login event extractor

l_passwd_pattern = re.compile("(&|^)password=(.*?)($|&)")
l_name_pattern = re.compile("(&|^)account=(.*?)($|&)")


def extract_login_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "users/login" not in httpmsg.uri:
        return

    properties = extract_common_properties(httpmsg)

    result = "F"
    body = httpmsg.resp_body or ""
    if body:
        try:
            body = get_json_obj(body)
            succ = body["code"]
            if succ == 200:
                result = "T"
        except Exception as err:
            pass

    body = httpmsg.req_body or ""
    login_name = extract_value_from_body(l_name_pattern, httpmsg.req_body)
    properties["result"] = result
    properties["password"] = get_md5(extract_value_from_body(l_passwd_pattern, httpmsg.req_body))
    properties["user_name"] = login_name
    properties["captcha"] = ""
    properties["remember_me"] = "F"
    properties["login_channel"] = "pc"
    properties["login_verification_type"] = "password"
    properties["uid"] = login_name

    return Event("nebula", "ACCOUNT_LOGIN", "", millis_now(), properties)


#  ##############Regist part##################
r_mobile_pattern = re.compile("(&|^)mobile=(.*?)($|&)")


def extract_regist_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "/user/regist" not in httpmsg.uri:
        return

    result = "F"
    body = httpmsg.resp_body or ""
    if body:
        try:
            body = get_json_obj(body)
            code = body["code"]
            if code == 200:
                result = "T"

        except Exception as err:
            pass

    properties = extract_common_properties(httpmsg)
    properties["result"] = result
    properties["register_realname"] = ""
    properties["register_channel"] = ""
    properties["email"] = ""
    properties["user_name"] = extract_value_from_body(r_mobile_pattern, httpmsg.req_body)
    properties["password"] = ""
    properties["captcha"] = ""
    properties["register_verification_token"] = ""
    properties["register_verification_token_type"] = ""
    return Event("nebula", "ACCOUNT_REGISTRATION", "", millis_now(), properties)
"""

def delete_pyc(data):
    r = []
    for e in data:
        if (e == '__init__.py') or ('pyc' in e):
            pass
        else:
            r.append(e)
    return r


#  ############Parser############################
class DefaultParser(Parser):
    def __init__(self):
        super(DefaultParser, self).__init__()
        self.http_msg_parsers = [extract_http_log_event]

    def name(self):
        return "default customparsers"

    def get_logbody_config(self):
        return ["login", "user"]

    def py_from_address(self):
        init_address = './nebula_sniffer/customparsers/lib'
        root = ''
        files = []
        for root, dirs, file in os.walk(init_address):
            files.extend(file)
        return (root, files)

    def events_from_dynamic(self, result, http_msg):
        # 动态脚本判断获取 event
        # 得到一个列表, 然后循环插入
        # 扫描lib文件夹的所有
        (root, all_py) = self.py_from_address()
        properties = extract_common_properties(http_msg)
        all_py = delete_pyc(all_py)
        for f in all_py:
            # path = "nebula_sniffer.nebula_sniffer.customparsers.lib." + f[0: -3]
            try:
                path = "nebula_sniffer.customparsers.lib." + f[0: -3]
                if not os.path.exists(path):
                    continue
                e = importlib.import_module(path)
                p = json.dumps(properties)
                out = e.event(p)
                out = json.loads(out)
                for o in out:
                    if o['event_result'] is True:
                        event_name = o['event_name']
                        properties = o['properties']
                        e = Event("nebula", event_name, "", millis_now(), properties)
                        result.append(e)
                    else:
                        pass
            except Exception as f:
                print('import error', f)

        return result

    def get_events_from_http_msg(self, http_msg):
        if not http_msg:
            return []

        result = list()
        for p in self.http_msg_parsers:
            try:
                ev = p(http_msg)
                if ev:
                    result.append(ev)
            except:
                logger.debug("fail to parse with {}".format(p))
        result = self.events_from_dynamic(result, http_msg)
        return result

    def get_events_from_text_msg(self, text_msg):
        return []

    def filter(self, msg):
        if not isinstance(msg, HttpMsg):
            return False

        return False


Parser.add_parser("default", DefaultParser())
