#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
from gevent.server import DatagramServer

from threathunter_common.metrics.metricsrecorder import MetricsRecorder

from .driver import Driver
from ..msg import TextMsg


class UDPServer(DatagramServer):
    def __init__(self, listener, recv_handler):
        super(UDPServer, self).__init__(listener)
        self.recv_handler = recv_handler

    def handle(self, data, address):  # pylint:disable=method-hidden
        self.recv_handler(data, address)


class SyslogTextDriver(Driver):
    def __init__(self, port):
        Driver.__init__(self)
        self.port = port
        self.logger = logging.getLogger("sniffer.syslogtext.{}".format(self.port))
        self.server = UDPServer(":{}".format(self.port), self._recv_msg_fn)
        self.data_mr = None
        self.error_mr = None

    def _recv_msg_fn(self, msg, addr):
        for m in msg.split("\n"):
            self._recv_msg_fn_in(m, addr)

    def _recv_msg_fn_in(self, msg, addr):
        try:
            if not msg:
                return
            self.add_input_data_metrics(addr)
            self.logger.debug("get syslog text msg %s from address %s", msg, addr)

            new_msg = TextMsg(msg)
            self.add_output_data_metrics(addr)
            self.logger.debug("get http msg from syslog text: %s", new_msg)
            self.put_msg(new_msg)

            return new_msg
        except Exception as ex:
            self.logger.error("fail to parse syslog data: %s", ex)

            self.add_error_metrics(addr, "data_parse", str(ex))
            self.add_drop_data_metrics(addr, "data_parse")
            self.add_dropped_msgs(1)

    # ## For metrics
    def add_data_metrics(self, source, data_type, subtype=""):
        tags = {"source_type": "syslogtext", "source": source, "type": data_type, "port": self.port, "subtype": subtype}
        self.data_mr.record(1, tags)

    def add_input_data_metrics(self, source):
        return self.add_data_metrics(source, "input")

    def add_output_data_metrics(self, source):
        return self.add_data_metrics(source, "output")

    def add_drop_data_metrics(self, source, reason=""):
        return self.add_data_metrics(source, "drop", reason)

    def add_error_metrics(self, source, data_type, subtype=""):
        tags = {"source_type": "syslogtext", "source": source, "type": data_type, "port": self.port, "subtype": subtype}
        self.error_mr.record(1, tags)

    def start(self):
        self.logger.info("start syslog text driver")

        self.data_mr = MetricsRecorder("sniffer.driver.data")
        self.error_mr = MetricsRecorder("sniffer.driver.error")
        self.server.start()

    def stop(self):
        pass

    def is_alive(self):
        return True


if __name__ == "__main__":
    pass
