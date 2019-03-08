#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import re
import json
import time
from threathunter_common.metrics.metricsrecorder import MetricsRecorder

from .driver import Driver
from ..msg import HttpMsg
from ..befilteredexception import BeFilteredException
from .logstashserver import LogStashServer


class LogstashDriver(Driver):
    def __init__(self, port):
        Driver.__init__(self)
        self.port = port
        self.logger = logging.getLogger("sniffer.logstash.{}".format(self.port))
        self.server = LogStashServer(self._recv_msg_fn, ("0.0.0.0", int(self.port)))
        self.data_mr = None
        self.error_mr = None
        self.pattern = re.compile(r'^(?P<src_ip>[^\s]+) (?P<server_ip>[^\s]+)\s+\[[^\]]+] '
                                  r'(?P<host>[^\s]+) [^\s]+ "(?P<method>[^\s]+) (?P<uri>[^\s]+) [^\s]+ '
                                  r'(?P<status>[^\s]+) (?P<server_bytes>[^\s]+) [^\s]+ "(?P<referer>[^\"]+)" '
                                  r'"(?P<ua>[^\"]+)" .*')
        self.count = 0

    def _recv_msg_fn(self, msg, addr=""):
        for m in msg.split("\n"):
            self._recv_msg_fn_in(m, addr)

    def _recv_msg_fn_in(self, msg, addr):
        """
        example
        36.7.130.69 - [16/Jul/2017:23:58:42 +0800] ffp.hnair.com 1 "GET /FFPClub/upload/index/e9b1bb4a-e1dd-47e1-8699-9828685004b4.jpg HTTP/1.1" 200 487752 - "http://ffp.hnair.com/FFPClub/cn/index.html" "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0; NetworkBench/8.0.1.309-4992258-2148837) like Gecko" "-"

        汽车之家
        {"@timestamp_scs": "2017-09-21T12:18:17+08:00", "scs_request_uri": "/site-wap/my/transferin.htm",
         "scs_status": "200", "scs_bytes_sent": "26829", "scs_upstream_cache_status": "-", "scs_request_time": "0.570",
         "scs_upstream_response_time": "0.570", "scs_host": "pay.autohome.com.cn", "scs_remote_addr": "10.20.2.23",
         "scs_server_addr": "10.20.252.33", "scs_upstream_addr": "10.20.252.20:8253", "scs_upstream_status": "200",
         "scs_http_referer": "https://pay.autohome.com.cn/site-wap/activity/upin.htm?__sub_from=A2002027782510100",
         "scs_http_user_agent": "Mozilla/5.0 (Linux; Android 5.1; OPPO A59m Build/LMY47I; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/43.0.2357.121 Mobile Safari/537.36 autohomeapp/1.0+%28auto_android%3B8.4.0%3BOi-CR_rnyywoODk5jv0ve5luKLNxl7AfnEsGsBBPNdWdDtP8ZDdRHA3ePFiDlWOr%3B5.1%3BOPPO%2BA59m%29 auto_android/8.4.0 nettype/wifi",
         "scs_http_X_Forwarded_For": "220.166.199.167"}

        """

        try:
            if not msg:
                return
            msg = msg.strip()
            if not msg:
                return

            self.add_input_data_metrics(addr)
            self.logger.debug("get log msg %s from address %s", msg, addr)

            # 汽车之家
            try:
                msg = json.loads(msg)
            except Exception as e:
                return

            c_ip = msg.get('scs_http_X_Forwarded_For', '')
            if c_ip:
                c_ip_group = c_ip.split(',')
                if c_ip_group:
                    c_ip = c_ip_group[-1]
            c_port = 0
            s_port = 80
            c_bytes = 0
            s_bytes = msg.get('scs_bytes_sent', 0)
            if s_bytes == '-':
                s_bytes = 0
            else:
                s_bytes = int(s_bytes)
            status = int(msg.get('scs_status', 0))
            req_body = ''

            args = dict()
            args["method"] = 'GET'
            args["host"] = msg.get('scs_host', '').lower()
            args["uri"] = msg.get('scs_request_uri', '').lower()
            args["referer"] = msg.get('scs_http_referer', '').lower()
            args["user_agent"] = msg.get('scs_http_user_agent', '').lower()
            args["status_code"] = status
            args["status_msg"] = ""
            args["source_ip"] = c_ip
            args["source_port"] = c_port
            args["dest_ip"] = ''
            args["dest_port"] = s_port

            request_time = 0.0
            try:
                ctime = msg['@timestamp_scs']
                ctime = ctime.replace('T', ' ').replace('+08:00', '')
                time_array = time.strptime(ctime, "%Y-%m-%d %H:%M:%S")
                # 转换成时间戳
                request_time = time.mktime(time_array)
            except Exception as e:
                pass

            args["req_time"] = int(request_time * 1000)

            # headers
            args["req_headers"] = {}

            args["resp_headers"] = {}

            # no body for logstash
            args["log_body"] = False
            args["req_body"] = ""
            args["resp_body"] = ""
            args["req_body_len"] = c_bytes
            args["resp_body_len"] = s_bytes
            args["req_content_type"] = ''
            args["resp_content_type"] = ''
            args["req_body"] = req_body

            args["debug_processing"] = False

            self.logger.debug("get http data from logstash: %s", args)
            try:
                new_msg = HttpMsg(**args)
            except BeFilteredException as bfe:
                self.add_drop_data_metrics(addr, bfe.type)
                return
            except Exception as err:
                # drop improper message
                self.add_drop_data_metrics(addr, str(err))
                self.add_error_metrics(addr, "msg_parse", str(err))
                self.logger.debug("fail to parse: %s", args)
                return

            self.add_output_data_metrics(addr)
            self.logger.debug("get http msg from logstash: %s", new_msg)
            self.put_msg(new_msg)
            self.count += 1
            if self.count % 1000 == 0:
                print "has put {}".format(self.count)

            return new_msg
        except Exception as ex:
            print 7777, ex
            self.logger.error("fail to parse logstash data: %s", ex)

            self.add_error_metrics(addr, "data_parse", str(ex))
            self.add_drop_data_metrics(addr, "data_parse")
            self.add_dropped_msgs(1)

    # ## For metrics
    def add_data_metrics(self, source, data_type, subtype=""):
        tags = {"source_type": "logstash", "source": source, "type": data_type, "port": self.port, "subtype": subtype}
        self.data_mr.record(1, tags)

    def add_input_data_metrics(self, source):
        return self.add_data_metrics(source, "input")

    def add_output_data_metrics(self, source):
        return self.add_data_metrics(source, "output")

    def add_drop_data_metrics(self, source, reason=""):
        return self.add_data_metrics(source, "drop", reason)

    def add_error_metrics(self, source, data_type, subtype=""):
        tags = {"source_type": "logstash", "source": source, "type": data_type, "port": self.port, "subtype": subtype}
        self.error_mr.record(1, tags)

    def start(self):
        self.logger.info("start logstash driver")
        self.data_mr = MetricsRecorder("sniffer.driver.data")
        self.error_mr = MetricsRecorder("sniffer.driver.error")
        self.server.start_running()

    def stop(self):
        self.server.stop()

    def is_alive(self):
        return True
