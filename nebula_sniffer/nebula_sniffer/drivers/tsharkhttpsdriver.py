#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Use tshark to detect https traffic.
"""
import gzip
import traceback
import os
import pexpect
import subprocess
import signal
import logging
import gevent.queue

import threathunter_common.util
from threathunter_common.util import millis_now, run_in_thread, utf8
from threathunter_common.metrics.metricsrecorder import MetricsRecorder
from complexconfig.configcontainer import configcontainer

from .driver import Driver
from ..msg import HttpMsg
from ..cache import Cache
from ..utils import expand_ports, is_linux
from ..befilteredexception import BeFilteredException


def get_tshark_home(given=None):
    if given:
        return given

    result = os.environ.get("TSHARK_HOME")
    if result:
        return result

    cmd_result = subprocess.Popen(["which", "tshark"], stdout=subprocess.PIPE,
                                  stdin=subprocess.PIPE).communicate()[0]
    if cmd_result:
        result = os.path.dirname(cmd_result)
        if result:
            return result

    raise RuntimeError("Cannot find tshark")


def extract_body_from_text(text):
    if not text:
        return ""
    text = utf8(text)
    result = bytearray()
    length = len(text)
    cursor = 0
    while cursor < length:
        ch = text[cursor]
        if ch == "\\" and cursor <= length - 4:
            octvalue = text[cursor + 1:cursor + 4]
            if octvalue.isdigit():
                result.append(int(octvalue, 8))
                cursor += 4
                continue

        result.append(ch)
        cursor += 1

    return str(result)


def extract_body_from_data(data, text, content_encoding):
    if data and ":" in data:
        data = data.replace(",", ":")  # for gzip
        data = data.split(":")
        data = map(lambda x: int(x, 16), data)
        data = str(bytearray(data))

        if content_encoding:
            if "gzip" in content_encoding.lower():
                try:
                    data = gzip.zlib.decompress(data, 16 | gzip.zlib.MAX_WBITS)
                except Exception as it_may_not_be_compressed:
                    pass

        return data

    # try to get body from text
    return extract_body_from_text(text)


class TsharkHttpsDriver(Driver):
    def __init__(self, interface="lo0", ports=(80, 8080, 8443),
                 key_place="/Users/lw/sslprivatekey/server.key.unencrypted", bpf_filter=None):
        Driver.__init__(self)
        self.ports = configcontainer.get_config("sniffer").get_string("filter.traffic.server_ports", "") \
                     or ports
        self.ports = expand_ports(self.ports)
        self.key_place = key_place
        self.interface = interface
        self.bpf_filter = bpf_filter

        self.sub_task = None
        self.client_task = None
        self.running = False

        # cache used for building the http message
        self.cache = Cache(50000, ttl=30)
        self.TIMEOUT = 30  # 30s timeout
        self.last_check = millis_now()

        self.logger = logging.getLogger("sniffer.tshark.{}".format(interface))
        self.data_mr = None
        self.error_mr = None
        self.fixed_tags = {"ports": str(self.ports), "interface": self.interface}

    def start(self):
        if self.running:
            return

        self.logger.info("start tshark driver on interface %s for ports %s, with bpf filter %s", self.interface,
                         self.ports, self.bpf_filter)

        self.running = True
        self.data_mr = MetricsRecorder("sniffer.driver.data")
        self.error_mr = MetricsRecorder("sniffer.driver.error")
        port_filter = " or ".join(["tcp port {}".format(port) for port in self.ports])
        if self.bpf_filter:
            port_filter = "({}) and ({})".format(port_filter, self.bpf_filter)
        tshark_home = get_tshark_home()
        if not tshark_home:
            raise RuntimeError("tshark is not find")
        self.logger.info("find tshark at %s", tshark_home)
        command = (is_linux() and "sudo " or "") + """%(tshark_home)s/tshark -o ssl.desegment_ssl_application_data:TRUE
                            -o ssl.desegment_ssl_records:TRUE
                            -o ssl.keys_list:"0.0.0.0","443","http","/home/threathunter/private.key"
                            -f "%(port_filter)s"
                            -i %(interface)s
                            -Y "http.request or http.response"
                            -T fields -Eseparator=/t
                            -e http
                            -e http.request
                            -e ip.src
                            -e tcp.srcport
                            -e ip.dst
                            -e tcp.dstport
                            -e http.request.method
                            -e http.host
                            -e http.request.uri
                            -e http.request.full_uri
                            -e http.user_agent
                            -e http.content_length
                            -e http.content_type
                            -e http.response.code
                            -e http.response.phrase
                            -e http.content_encoding
                            -e http.cookie
                            -e http.set_cookie
                            -e http.referer
                            -e data.data
                            -e text
                            """ % ({"tshark_home": tshark_home, "port_filter": port_filter,
                                    "interface": self.interface})
        environments = dict()
        environments["PCAP_PF_RING_CLUSTER_ID"] = "14"
        environments["PCAP_PF_RING_APPNAME"] = "tshark-" + self.interface
        environments["PCAP_PF_RING_USE_CLUSTER_PER_FLOW_4_TUPLE"] = "1"
        environments["LD_LIBRARY_PATH"] = "/usr/local/lib64"
        self.logger.info("start tshark command: %s", command)
        self.sub_task = pexpect.spawn(command, env=environments, timeout=3600)
        import atexit
        atexit.register(self.stop)
        # establish client
        gevent.sleep(2)
        self.client_task = run_in_thread(self.process_input)
        return

    def stop(self):
        self.logger.info("stop tshark driver on interface %s for ports %s, with bpf filter %s", self.interface,
                         self.ports, self.bpf_filter)
        self.running = False
        if self.client_task:
            self.client_task.join(timeout=2)
            self.client_task = None

        if self.sub_task is not None:
            try:
                if self.sub_task.isalive():
                    os.killpg(self.sub_task.pid, signal.SIGTERM)
                    self.sub_task.wait()
            except Exception as ex:
                traceback.print_exc()
                self.logger.error("fail to kill subprocess %s", ex)
            self.sub_task = None

    def is_alive(self):
        return self.sub_task is not None and self.sub_task.isalive()

    def process_input(self):
        while self.running:
            try:
                self.sub_task.expect('\n')
                line = self.sub_task.before
                self.process_http_line(line)
            except pexpect.EOF:
                break
            except Exception as err:
                self.logger.error("fail to process line %s", err)
                self.add_dropped_msgs(1)
                continue

    def process_http_line(self, line):
        try:
            if not line or not line.startswith("http"):
                self.logger.error("invalid http data, could be error msg: %s", line)
                return

            self.add_data_metrics("input")
            self.logger.debug("tshark get line %s", line)
            fields = line.split("\t", 20)
            if len(fields) < 21:
                self.add_drop_data_metrics("wrong number fields")
                self.add_error_metrics("wrong number fields")
                raise RuntimeError("invalid fields")
            try:
                flag, is_request, src, srcport, dst, dstport, method, host, uri, full_uri, user_agent, content_length, \
                content_type, code, phase, content_encoding, cookie, set_cookie, referer, data, text = tuple(fields)
            except Exception as error:
                self.add_drop_data_metrics("split fields")
                self.add_error_metrics("split fields")
                self.logger.error("fail to split fields from line, error: %s", error)
                raise RuntimeError("fail to parse fields: {}".format(fields))

            if is_request:
                key = (src, srcport, dst, dstport)
            else:
                key = (dst, dstport, src, srcport)

            if is_request:
                self.add_data_metrics("input_request")
                if self.cache.get(key):
                    # there are previous request not processed
                    self.logger.warn("dropping previous incomplete request for key: {}".format(key))
                    del self.cache[key]
                    self.add_dropped_msgs(1)
                    self.add_error_metrics("stale request")

                http_record = dict()
                http_record["source_ip"] = src
                http_record["source_port"] = int(srcport)
                http_record["dest_ip"] = dst
                http_record["dest_port"] = int(dstport)

                http_record["method"] = method.upper()
                http_record["host"] = host
                http_record["uri"] = uri or ""
                http_record["user_agent"] = user_agent
                http_record["referer"] = referer or ""
                http_record["req_body_len"] = int(content_length or 0)
                http_record["req_headers"] = dict()
                http_record["req_content_type"] = content_type or ""
                if "POST" == http_record["method"] and http_record["req_body_len"] > 0:
                    body = extract_body_from_data(data, text, content_encoding)
                    http_record["log_body"] = True
                else:
                    body = ""
                    http_record["log_body"] = False
                http_record["req_body"] = body

                current = millis_now()
                http_record["ts"] = current

                cookie = threathunter_common.util.text(cookie or "")
                http_record["req_headers"] = {"COOKIE": cookie}

                self.cache[key] = http_record
                # add an entry for background check

            else:
                # process the response
                self.add_data_metrics("input_response")
                http_record = self.cache.get(key, {})
                if not http_record:
                    self.logger.warn("can't find matching request")
                    self.add_drop_data_metrics("no matching request")
                    self.add_error_metrics("no matching request")
                    return

                http_record["status_code"] = int(code or 0)
                http_record["status_msg"] = phase
                http_record["resp_body_len"] = int(content_length or 0)
                http_record["resp_content_type"] = content_type or ""
                if http_record["log_body"] and http_record["method"] == "POST" and http_record["resp_body_len"] > 0:
                    body = extract_body_from_data(data, text, content_encoding)
                else:
                    body = ""
                http_record["resp_body"] = body
                if not http_record["resp_body_len"]:
                    # in case the gzip response
                    http_record["resp_body_len"] = len(body)

                http_record["resp_headers"] = dict()
                set_cookie = threathunter_common.util.text(set_cookie or "")
                http_record["resp_headers"] = {"SET-COOKIE": set_cookie}
                http_record["debug_processing"] = False
                http_record["debug_processing"] = True
                http_record["resp_content_type"] = content_type
                http_record["req_time"] = millis_now() - http_record["ts"]

                self.logger.debug("get http data from tshark: %s", http_record)
                try:
                    new_msg = HttpMsg(**http_record)
                except BeFilteredException as bpf:
                    self.add_drop_data_metrics(bpf.type)
                    return
                except Exception as err:
                    self.add_drop_data_metrics(str(err))
                    self.add_error_metrics("msg_parse")
                    return

                self.logger.debug("get http msg from tshark: %s", new_msg)
                self.add_data_metrics("output")
                self.put_msg(new_msg)
                del self.cache[key]
                return new_msg
        except Exception as err:
            self.add_error_metrics("data_parse")
            self.add_drop_data_metrics("data_parse")
            self.logger.error("fail to process tshark, error: %s", err)
            traceback.print_exc()
            raise err

    # ## For metrics
    def add_data_metrics(self, data_type, subtype=""):
        tags = {"source_type": "tshark", "interface": self.interface, "type": data_type, "port": str(self.ports),
                "subtype": subtype}
        self.data_mr.record(1, tags)

    def add_input_data_metrics(self):
        return self.add_data_metrics("input")

    def add_output_data_metrics(self):
        return self.add_data_metrics("output")

    def add_drop_data_metrics(self, reason=""):
        return self.add_data_metrics("drop", reason)

    def add_error_metrics(self, data_type):
        tags = {"source_type": "tshark", "interface": self.interface, "type": data_type, "port": str(self.ports)}
        self.error_mr.record(1, tags)
