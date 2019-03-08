#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from json import loads
from gevent.server import DatagramServer

from threathunter_common.metrics.metricsrecorder import MetricsRecorder

from .driver import Driver


class UDPServer(DatagramServer):
    def __init__(self, listener, recv_handler):
        super(UDPServer, self).__init__(listener)
        self.recv_handler = recv_handler

    def handle(self, data, address):  # pylint:disable=method-hidden
        self.recv_handler(data, address)


class PacketbeatDriver(Driver):
    def __init__(self, port):
        Driver.__init__(self)
        self.port = port
        self.logger = logging.getLogger("sniffer.packetbeat.{}".format(self.port))
        self.server = UDPServer(":{}".format(self.port), self._recv_msg_fn)
        self.data_mr = None
        self.error_mr = None

    def _recv_msg_fn(self, msg, addr):
        for m in msg.split("\n"):
            self._recv_msg_fn_in(m, addr)

    def _recv_msg_fn_in(self, msg, addr):
        """
        msg:
        {u'ip': u'172.16.0.157', u'@timestamp': u'2016-06-30T07:27:28.836Z', u'direction': u'in', u'query':
        u'GET /index', u'port': 9001, u'client_server': u'', u'bytes_in': 406, u'params': u'a=22',
        u'responsetime': 0, u'proc': u'', u'method': u'GET', u'status': u'OK', u'client_ip': u'172.16.0.48',
        u'http': {u'content_length': 26, u'phrase': u'OK', u'code': 200}, u'beat': {u'hostname':
        u'nginx.local', u'name': u'nginx.local'}, u'bytes_out': 216, u'client_port': 60966, u'path': u'/index',
        u'response': u'HTTP/1.1 200 OK\r\nServer: nginx/1.10.0\r\nDate: Thu, 30 Jun 2016
        07:27:28 GMT\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection:
        keep-alive\r\nContent-Encoding: gzip
        \r\n\r\n\x1f\ufffd\x08\x00\x00\x00\x00\x00\x00\x03\ufffdH\ufffd\ufffd\ufffd\ufffd\x02\x00 0:6\x06\x00\x00\x00',
        u'count': 1, u'type': u'http', u'request': u'GET /index?a=22
        HTTP/1.1\r\nHost: 172.16.0.157:9001\r\nConnection: keep-alive\r\nCache-Control:
        max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
        (KHTML, like Gecko) Chrome/51.0.2704.84 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,
        application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Encoding: gzip,
        deflate, sdch\r\nAccept-Language: zh-CN,zh;q=0.8\r\n\r\n', u'server': u'', u'client_proc': u''}
        """
        try:
            if not msg:
                return
            print loads(msg), '!!!'
            self.add_input_data_metrics(addr)
            self.logger.debug("pkt msg %s from address %s", msg, addr)
            """
            args = dict()
            args["method"] = method
            args["host"] = host
            args["uri"] = uri
            args["referer"] = referer
            args["user_agent"] = agent
            args["status_code"] = status
            args["status_msg"] = ""
            args["source_ip"] = c_ip
            args["source_port"] = c_port
            args["dest_ip"] = s_ip
            args["dest_port"] = s_port

            request_time = float(request_time or 0)
            args["req_time"] = int(request_time * 1000)

            # headers
            args["req_headers"] = {"COOKIE": cookie} if cookie else {}
            if x_forward:
                args["req_headers"]["X-FORWARDED-FOR"] = x_forward

            args["resp_headers"] = {"SET-COOKIE": set_cookie} if set_cookie else {}

            # no body for syslog
            args["log_body"] = False
            args["req_body_len"] = c_bytes
            args["resp_body_len"] = s_bytes
            args["req_content_type"] = req_content_type
            args["resp_content_type"] = resp_content_type
            args["req_body"] = req_body
            args["resp_body"] = resp_body

            args["debug_processing"] = debughelper.DEBUG_FLAG in cookie

            self.logger.debug("get http data from pkt: %s", args)
            try:
                new_msg = HttpMsg(**args)
            except BeFilteredException as bfe:
                self.add_drop_data_metrics(addr, bfe.type)
                return
            except:
                # drop improper message
                self.add_drop_data_metrics(addr, "msg_parse")
                self.add_error_metrics(addr, "msg_parse")
                return

            self.add_output_data_metrics(addr)
            self.logger.debug("get http msg from syslog: %s", new_msg)
            debughelper.debug("syslog get msg {}".format(str(new_msg)), args["debug_processing"])
            self.put_msg(new_msg)
            """

            return msg
        except Exception as ex:
            self.logger.error("fail to parse syslog data: %s", ex)

            self.add_error_metrics(addr, "data_parse")
            self.add_drop_data_metrics(addr, "data_parse")
            self.add_dropped_msgs(1)

    #  For metrics
    def add_data_metrics(self, source, data_type, subtype=""):
        tags = {"source_type": "syslog", "source": source, "type": data_type, "port": self.port, "subtype": subtype}
        self.data_mr.record(1, tags)

    def add_input_data_metrics(self, source):
        return self.add_data_metrics(source, "input")

    def add_output_data_metrics(self, source):
        return self.add_data_metrics(source, "output")

    def add_drop_data_metrics(self, source, reason=""):
        return self.add_data_metrics(source, "drop", reason)

    def add_error_metrics(self, source, data_type):
        tags = {"source_type": "syslog", "source": source, "type": data_type, "port": self.port}
        self.error_mr.record(1, tags)

    def start(self):
        self.logger.info("start pkt driver")

        self.data_mr = MetricsRecorder("sniffer.driver.data")
        self.error_mr = MetricsRecorder("sniffer.driver.error")
        self.server.start()

    def stop(self):
        pass

    def is_alive(self):
        return True


if __name__ == "__main__":
    pass
