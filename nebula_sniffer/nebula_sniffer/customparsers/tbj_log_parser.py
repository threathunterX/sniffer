#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re

from ..parser import Parser, extract_http_log_event
from ..msg import HttpMsg

__author__ = "nebula"


#  ############Parser############################
class TBJLogParser(Parser):

    def __init__(self):
        super(TBJLogParser, self).__init__()
        self.pattern = re.compile("\\[.*?\\]")

    def name(self):
        return "zailushang customparsers"

    def parse_httpmsg(self, msg):
        try:
            if '"' not in msg:
                return None

            body = msg[msg.index('"'):]
            body = body.strip()
            if body.startswith("\""):
                body = body[1:]
            if body.endswith("\""):
                body = body[:-1]

            parts = body.split('" "')
            c_ip, c_port, s_ip, s_port, c_totalbytes, c_bytes, s_bytes, uri, host, agent, status, cookie, method, \
            referer = parts[:14]
            c_port = int(c_port)
            s_port = int(s_port)
            c_bytes = 0 if c_bytes == "-" else int(c_bytes)
            s_bytes = 0 if s_bytes == "-" else int(s_bytes)
            status = int(status)

            args = dict()
            args["method"] = method.upper()
            args["host"] = host.lower()
            args["uri"] = uri
            args["uriraw"] = uri
            args["referer"] = referer
            args["user_agent"] = agent.lower()
            args["req_body_len"] = c_bytes
            args["resp_body_len"] = s_bytes
            args["status_code"] = status
            args["status_msg"] = ""
            args["source_ip"] = c_ip
            args["source_port"] = c_port
            args["dest_ip"] = s_ip
            args["dest_port"] = s_port
            if len(parts) >= 15:
                ts_str = parts[14]
                if "\"" in ts_str:
                    ts_str = ts_str[:ts_str.index("\"")]
                ts = float(ts_str)
            else:
                ts = 0.0
            secs = int(ts)
            msecs = int(1000 * (ts - secs))
            args["ts_secs"] = secs
            args["ts_msecs"] = msecs

            args["req_headers"] = {"Cookie": cookie} if cookie else {}
            args["resp_headers"] = {}
            args["debug_processing"] = False

            args["log_body"] = False
            args["req_body"] = ""
            args["resp_body"] = ""

            url = host + uri
            for lu in self.get_logbody_config():
                if lu in url:
                    args["log_body"] = True
            if args["log_body"] and len(msg) >= (c_bytes + s_bytes):
                args["req_body"] = msg[(-1 * (c_bytes + s_bytes)):(-1 * s_bytes)]
                args["resp_body"] = msg[(-1 * s_bytes):]

            new_msg = HttpMsg(**args)
            return new_msg
        except Exception as ignore:
            return []

    def parse_goodsmsg(self, msg):
        return 1

    def get_logbody_config(self):
        return []

    def get_events_from_http_msg(self, http_msg):
        return [extract_http_log_event(http_msg)]

    def get_events_from_text_msg(self, text_msg):
        http = self.parse_httpmsg(text_msg.text)
        if http:
            if self.filter(http):
                return []
            return [extract_http_log_event(http)]

        goods = self.parse_goodsmsg(text_msg)
        if goods:
            return [goods]

        raise RuntimeError("unrecognized msg {}".format(text_msg.text))

    def filter(self, httpmsg):
        if isinstance(httpmsg, HttpMsg):
            if httpmsg.source_ip == "-":
                return True
        return False


Parser.add_parser("zls", TBJLogParser())
