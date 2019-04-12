#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from gevent.server import DatagramServer

from threathunter_common.metrics.metricsrecorder import MetricsRecorder

from .driver import Driver
from ..msg import HttpMsg
from ..befilteredexception import BeFilteredException


class UDPServer(DatagramServer):
    def __init__(self, listener, recv_handler):
        super(UDPServer, self).__init__(listener)
        self.recv_handler = recv_handler

    def handle(self, data, address):  # pylint:disable=method-hidden
        self.recv_handler(data, address)


class SyslogDriver(Driver):
    def __init__(self, port):
        Driver.__init__(self, "syslog.{}".format(self.port))
        self.port = port
        self.server = UDPServer(":{}".format(self.port), self._recv_msg_fn)
        self.data_mr = None
        self.error_mr = None

    def _recv_msg_fn(self, msg, addr):
        for m in msg.split("\n"):
            self._recv_msg_fn_in(m, addr)

    def _recv_msg_fn_in(self, msg, addr):
        """
        nginx format:
        log_format httplog '"$remote_addr" "$remote_port" "$server_addr" "$server_port" "$request_length" \
        "$content_length" "$body_bytes_sent" "$request_uri" "$host" "$http_user_agent" "$status" "$http_cookie" \
        "$request_method" "$http_referer" "$http_x_forwarded_for" "$request_time" "$sent_http_set_cookie" \
        "$content_type" "$upstream_http_content_type" "$request_data"';

        msg example:
        <14>Jun 26 17:13:21 10-10-92-198 NGINX[26113]: "114.242.250.233" "65033" "10.10.92.198" "80" "726" "134" \
        "9443" "/gateway/shop/getStroeForDistance" "m.lechebang.com" "Mozilla/5.0 (iPhone; CPU iPhone OS 8_1_3
        like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Mobile/12B466 MicroMessenger/6.1.4 NetType/3G+" "200" \
        "-" "POST" "http://m.lechebang.com/webapp/shop/list?cityId=10101&locationId=0&brandTypeId=\
        6454&maintenancePlanId=227223&oilInfoId=3906" "0.114"
        """

        try:
            if not msg:
                return
            self.add_input_data_metrics(addr)
            self.logger.debug("get syslog msg %s from address %s", msg, addr)
            # remove the header
            msg = msg.replace('\\\\x22', '\\x22')
            msg = msg.replace('\\x', '\\u00')  # for json
            msg = msg.strip()
            import json
            data = json.loads(msg)
            c_port = int(data["Client_Port"] or 0)
            status = int(data["Status"] or 0)

            c_ip = data['IP']
            cookie = data["Cookie"]
            host = data['Domain']
            referer = data['Referer']
            method = data['Method']
            agent = data['Agent']
            url = data['URL']
            query = data['Get']
            body = data['Post']

            if cookie == "-":
                cookie = ''
            if host == "-":
                host = ''
            if referer == "-":
                referer = ''
            if method == "-":
                method = ''
            if agent == "-":
                agent = ''
            if url == "-":
                url = ''
            if query == "-":
                query = ''
            if body == "-":
                body = ''

            if query:
                url = url + "?" + query

            s_port = 0
            c_bytes = 0
            s_bytes = int(data.get("Bytes")) or 0
            req_body = body

            args = dict()
            args["method"] = method
            args["host"] = host
            args["uri"] = url
            args["referer"] = referer
            args["user_agent"] = agent
            args["status_code"] = status
            args["status_msg"] = ""
            args["source_ip"] = c_ip
            args["source_port"] = c_port
            args["dest_ip"] = ''
            args["dest_port"] = s_port

            request_time = float(data['Client_Request_Time'] or 0)
            args["req_time"] = int(request_time * 1000)

            # headers
            args["req_headers"] = {"COOKIE": cookie} if cookie else {}
            args["resp_headers"] = {}

            if req_body.startswith("{"):
                req_content_type = 'application/json'
            elif req_body:
                req_content_type = 'application/x-www-form-urlencoded'
            else:
                req_content_type = ''

            resp_content_type = ''

            # no body for syslog
            args["log_body"] = False
            args["req_body"] = ""
            args["resp_body"] = ""
            args["req_body_len"] = c_bytes
            args["resp_body_len"] = s_bytes
            args["req_content_type"] = req_content_type
            args["resp_content_type"] = resp_content_type
            args["req_body"] = req_body

            args["debug_processing"] = False

            self.logger.debug("get http data from syslog: %s", args)
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
            self.logger.debug("get http msg from syslog: %s", new_msg)
            self.put_msg(new_msg)

            return new_msg
        except Exception as ex:
            self.logger.error("fail to parse syslog data: %s", ex)

            self.add_error_metrics(addr, "data_parse", str(ex))
            self.add_drop_data_metrics(addr, "data_parse")
            self.add_dropped_msgs(1)

    # ## For metrics
    def add_data_metrics(self, source, data_type, subtype=""):
        tags = {"source_type": "syslog", "source": source, "type": data_type, "port": self.port, "subtype": subtype}
        self.data_mr.record(1, tags)

    def add_input_data_metrics(self, source):
        return self.add_data_metrics(source, "input")

    def add_output_data_metrics(self, source):
        return self.add_data_metrics(source, "output")

    def add_drop_data_metrics(self, source, reason=""):
        return self.add_data_metrics(source, "drop", reason)

    def add_error_metrics(self, source, data_type, subtype=""):
        tags = {"source_type": "syslog", "source": source, "type": data_type, "port": self.port, "subtype": subtype}
        self.error_mr.record(1, tags)

    def start(self):
        self.logger.info("start syslog driver")

        self.data_mr = MetricsRecorder("sniffer.driver.data")
        self.error_mr = MetricsRecorder("sniffer.driver.error")
        self.server.start()

    def stop(self):
        self.server.stop()

    def is_alive(self):
        return True


if __name__ == "__main__":
    s = SyslogDriver(12)
    msg = "2015-07-15 22:25:58 [REQUEST_URI:/ajax/indexApi/syncServerTime?_=1436970358416][HTTP_USER_AGENT:Mozilla" \
          "/5.0 (iPhone; CPU iPhone OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Mobile/12H143 " \
          "NewsArticle/4.7.0 JsSdk/2.0 NetType/WIFI (News 4.7.0 8.4)][REMOTE_ADDR:114.218.65.25][HTTP_REFERER:http:" \
          "//tao.117go.com/product/9833?switchPage=1&refer=%E6%9C%BA%E9%85%92%E8%87%AA%E7%94%B1%E8%A1%8C&id1=4]" \
          "[NETCOUNT:db(0),mc(0),redis(0),tbapi(0),trapi(0),solr(0)][WAITING:0.05889ms][DURATION:6.72698ms]"
    s.parse_httpmsg(msg)

    pass
