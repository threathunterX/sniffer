#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import json
import datetime
import time

from threathunter_common.geo.ip import is_private_ip
from threathunter_common.util import millis_now
from threathunter_common.event import Event

from ..parser import Parser, extract_common_properties, extract_http_log_event
from ..parserutil import extract_value_from_body, get_json_obj, get_md5
from ..msg import HttpMsg

__author__ = "nebula"

r"""
Login event extractor
"""
l_passwd_pattern = re.compile("(&|^)txtUserPwd=(.*?)($|&)")
l_name_pattern = re.compile("(&|^)txtUserMemberID=(.*?)($|&)")
l_captcha_pattern = re.compile("(&|^)txtCode=(.*?)($|&)")


def extract_login_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if httpmsg.uri != "/login.aspx":
        return

    properties = extract_common_properties(httpmsg)
    if 301 == httpmsg.status_code:
        result = "T"
    else:
        result = "F"
    properties["login_result"] = result

    body = httpmsg.req_body or ""

    properties["password"] = get_md5(extract_value_from_body(l_passwd_pattern, body))
    properties["login_name"] = extract_value_from_body(l_name_pattern, body)
    properties["login_type"] = "pc"
    properties["auth_msg"] = ""
    properties["autologin"] = False
    properties["captcha"] = extract_value_from_body(l_captcha_pattern, body)

    return Event("nebula", "loginlog", "", millis_now(), properties)


#  ##############Regist part##################
r_email_pattern = re.compile("(&|^)txt_email_netmember=(.*?)($|&)")
r_name_pattern = re.compile("(&|^)txt_phone_netmember=(.*?)($|&)")
r_passwd_pattern = re.compile("(&|^)txtRegisterPwd=(.*?)($|&)")
r_captcha_pattern = re.compile("(&|^)txtCode=(.*?)($|&)")


def extract_regist_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if httpmsg.uri != "/register.aspx":
        return

    properties = extract_common_properties(httpmsg)
    if "<title>登录注册 -华住酒店集团官网</title>" in httpmsg.resp_body:
        result = "T"
    else:
        result = "F"
    properties["regist_result"] = result

    body = httpmsg.req_body or ""

    properties["email"] = extract_value_from_body(r_email_pattern, body)
    properties["regist_name"] = extract_value_from_body(r_name_pattern, body)
    properties["password"] = get_md5(extract_value_from_body(r_passwd_pattern, body))
    properties["captcha"] = extract_value_from_body(r_captcha_pattern, body)
    return Event("nebula", "registlog", "", millis_now(), properties)


#  ##############password_modify##################
pwmodify_oldpwd_pattern = re.compile("(\\r\\n|^)oldPwd=(.*?)($|\\r\\n)")
pwmodify_newpwd_pattern = re.compile("(\\r\\n|^)newPwd=(.*?)($|\\r\\n)")


def extract_password_modify_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "asp.maininfo" in httpmsg.uri_stem and "_method=modifymemberpwd" in httpmsg.uri_query:
        pass
    else:
        return

    if httpmsg.status_code == 200 and "''" == httpmsg.resp_body.strip():
        result = "T"
    else:
        result = "F"

    properties = extract_common_properties(httpmsg)
    properties["result"] = result
    properties["old_password"] = get_md5(extract_value_from_body(pwmodify_oldpwd_pattern, httpmsg.req_body))
    properties["new_password"] = get_md5(extract_value_from_body(pwmodify_newpwd_pattern, httpmsg.req_body))

    return Event("nebula", "password_modify", httpmsg.source_ip, millis_now(), properties)


#  ##############password_verify##################
pwverify_pwd_pattern = re.compile("(\\r\\n|^)pwd=(.*?)($|\\r\\n)")


def extract_password_verify_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "asp.maininfo" in httpmsg.uri_stem and "_method=checkpassword" in httpmsg.uri_query:
        pass
    else:
        return

    if "false" == httpmsg.resp_body:
        result = "F"
    else:
        result = "T"

    properties = extract_common_properties(httpmsg)
    properties["result"] = result
    properties["password"] = get_md5(extract_value_from_body(pwverify_pwd_pattern, httpmsg.req_body))

    return Event("nebula", "password_verify", httpmsg.source_ip, millis_now(), properties)


#  ##############password_reset##################
pwreset_mobile_pattern = re.compile("(&|^)tbox_phoneMail=(.*?)($|&)")
pwreset_captcha1_pattern = re.compile("(&|^)valcode=(.*?)($|&)")
pwreset_captcha2_pattern = re.compile("(&|^)valcode2=(.*?)($|&)")
pwreset_auth_pattern = re.compile("(&|^)tbox_vCode=(.*?)($|&)")
pwreset_newpw_pattern = re.compile("(&|^)tbox_newpwd1=(.*?)($|&)")


def extract_password_reset_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "getpassword.aspx" not in httpmsg.uri_stem:
        return

    properties = extract_common_properties(httpmsg)
    result = "F"
    for header in httpmsg.resp_headers.itervalues():
        if "logined=1; expires=" in header:
            result = "T"
    properties["result"] = result
    properties["mobile"] = extract_value_from_body(pwreset_mobile_pattern, httpmsg.req_body)
    properties["captcha"] = extract_value_from_body(pwreset_captcha1_pattern, httpmsg.req_body) or \
                            extract_value_from_body(pwreset_captcha2_pattern, httpmsg.req_body)
    properties["auth_msg"] = extract_value_from_body(pwreset_auth_pattern, httpmsg.req_body)
    properties["new_password"] = get_md5(extract_value_from_body(pwreset_newpw_pattern, httpmsg.req_body))
    step = 1
    if "btn_step2" in httpmsg.req_body:
        step = 2
    elif "btn_step3" in httpmsg.req_body:
        step = 3

    properties["step"] = step

    return Event("nebula", "password_reset", httpmsg.source_ip, millis_now(), properties)


#  ##############order_submit##################
ordersubmit_hotelid_pattern = re.compile("(&|^)HotelID=(.*?)($|&)")
ordersubmit_sku_pattern = re.compile("(&|^)RoomTypeID=(.*?)($|&)")
ordersubmit_skucount_pattern = re.compile("(&|^)BookingCount=(.*?)($|&)")
ordersubmit_reservation_pattern = re.compile("(&|^)CheckInDate=(.*?)($|&)")
ordersubmit_cname_pattern = re.compile("(&|^)ContactName=(.*?)($|&)")
ordersubmit_cmail_pattern = re.compile("(&|^)ContactEMail=(.*?)($|&)")
ordersubmit_mobile_pattern = re.compile("(&|^)ContactMobile=(.*?)($|&)")


def extract_order_submit_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "order/submitbookingform" not in httpmsg.uri_stem:
        return

    properties = extract_common_properties(httpmsg)
    if "订单提交成功" in httpmsg.resp_body:
        result = "T"
    else:
        result = "F"
    body_json = get_json_obj(httpmsg.resp_body)
    properties["result"] = result
    properties["merchant"] = extract_value_from_body(ordersubmit_hotelid_pattern, httpmsg.req_body)
    properties["orderid"] = body_json["Data"]["BookingResult"]["PmsResvNo"]
    properties["spu"] = ""
    properties["sku"] = extract_value_from_body(ordersubmit_sku_pattern, httpmsg.req_body)
    properties["sku_count"] = extract_value_from_body(ordersubmit_skucount_pattern, httpmsg.req_body)
    reservation = extract_value_from_body(ordersubmit_reservation_pattern, httpmsg.req_body)
    if reservation:
        reservation = datetime.datetime.strptime(reservation, "%Y-%m-%d").timetuple()
        reservation = time.mktime(reservation) * 1000
        reservation = long(reservation)
    else:
        reservation = 0
    properties["reservation_time"] = reservation
    properties["c_name"] = extract_value_from_body(ordersubmit_cname_pattern, httpmsg.req_body)
    properties["email"] = extract_value_from_body(ordersubmit_cmail_pattern, httpmsg.req_body)
    properties["mobile"] = extract_value_from_body(ordersubmit_mobile_pattern, httpmsg.req_body)
    return Event("nebula", "order_submit", httpmsg.source_ip, millis_now(), properties)


#  ##############order_cancel##################
ordercancel_hotelid_pattern = re.compile("(\\r\\n|^)hotelid=(.*?)($|\\r\\n)")
ordercancel_orderid_pattern = re.compile("(\\r\\n|^)pmsResno=(.*?)($|\\r\\n)")


def extract_order_cancel_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "ajax/ordermanage" in httpmsg.uri_stem and "_method=cancelpms" in httpmsg.uri_query:
        # need process
        pass
    else:
        return

    properties = extract_common_properties(httpmsg)
    if "true" in httpmsg.resp_body:
        result = "T"
    else:
        result = "F"
    properties["result"] = result
    properties["merchant"] = extract_value_from_body(ordercancel_hotelid_pattern, httpmsg.req_body)
    properties["orderid"] = extract_value_from_body(ordercancel_orderid_pattern, httpmsg.req_body)
    return Event("nebula", "order_cancel", httpmsg.source_ip, millis_now(), properties)


#  ##############bind_mob_verify##################
mobverify_passwd_pattern = re.compile("(&|^)txtPassword=(.*?)($|&)")
mobverify_code_pattern = re.compile("(&|^)txtCode=(.*?)($|&)")


def extract_mob_verify_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "submobile.aspx" not in httpmsg.uri_stem:
        return

    properties = extract_common_properties(httpmsg)
    if "window.parent.location.href = '/myht/modify_newmobile.aspx'" in httpmsg.resp_body:
        result = "T"
    else:
        result = "F"
    properties["result"] = result
    properties["password"] = get_md5(extract_value_from_body(mobverify_passwd_pattern, httpmsg.req_body))
    properties["auth_msg"] = extract_value_from_body(mobverify_code_pattern, httpmsg.req_body)
    return Event("nebula", "bind_mob_verify", httpmsg.source_ip, millis_now(), properties)


#  ##############modify_newmobile##################
newmobile_mobile_pattern = re.compile("(&|^)txtMobile=(.*?)($|&)")
newmobile_code_pattern = re.compile("(&|^)txtCode=(.*?)($|&)")


def extract_modify_newmobile_log_event(httpmsg):
    if not isinstance(httpmsg, HttpMsg):
        return
    if httpmsg.method != "POST":
        return
    if "modify_newmobile.aspx" not in httpmsg.uri_stem:
        return

    properties = extract_common_properties(httpmsg)
    if "alert('修改成功')" in httpmsg.resp_body:
        result = "T"
    else:
        result = "F"
    properties["result"] = result
    properties["new_bind_mob"] = extract_value_from_body(newmobile_mobile_pattern, httpmsg.req_body)
    properties["auth_msg"] = extract_value_from_body(newmobile_code_pattern, httpmsg.req_body)
    return Event("nebula", "bind_mob_modify", httpmsg.source_ip, millis_now(), properties)


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


#  ############Parser############################
class HuazhuParser(Parser):

    def __init__(self):
        super(HuazhuParser, self).__init__()
        self.http_msg_parsers = [extract_http_log_event, extract_regist_log_event, extract_login_log_event,
                                 extract_order_cancel_log_event, extract_order_submit_log_event,
                                 extract_password_modify_log_event, extract_password_reset_log_event,
                                 extract_password_verify_log_event, extract_mob_verify_log_event,
                                 extract_modify_newmobile_log_event]

    def name(self):
        return "Huazhu customparsers"

    def get_logbody_config(self):
        return ["login", "regist", "asp.maininfo", "getpassword", "submitbookingform", "ordermanage", "submobile",
                "modify_newmobile"]

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

        if msg.dest_ip == "10.1.201.10":
            return False  # 华住官网

        if msg.dest_ip == "10.1.211.15":
            return False  # 华住商城

        return True


Parser.add_parser("huazhu", HuazhuParser())
