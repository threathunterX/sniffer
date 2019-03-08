#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys

reload(sys)
sys.setdefaultencoding('utf-8')
import subprocess
import signal
import datetime
import atexit
import traceback
import logging
import os
import gevent.queue
import settings
import broker
import ipaddress
# threathunter fx
from threathunter_common.util import millis_now
from threathunter_common.metrics.metricsrecorder import MetricsRecorder

# relative import
from .driver import Driver
from ..msg import HttpMsg
from ..befilteredexception import BeFilteredException
from ..utils import expand_ports

__author__ = 'wb'

"""
Use BRO to detect http traffic.
"""
# config items
from complexconfig.configcontainer import configcontainer

sniffer_config = configcontainer.get_config("sniffer")
suffix_config = sniffer_config.item(key="filter.static.suffixes", caching=60,
                                    default=",".join(["gif", "png", "ico", "css", "js", "csv", "txt", "jpeg", "jpg",
                                                      "woff", "ttf"]))
filtered_hosts_config = sniffer_config.item(key="filter.traffic.domains", caching=60, default="")
filtered_urls_config = sniffer_config.item(key="filter.traffic.urls", caching=60, default="")
filtered_clients_config = sniffer_config.item(key="filter.traffic.client_ips", caching=60, default="")
filtered_servers_config = sniffer_config.item(key="filter.traffic.server_ips", caching=60, default="")


def get_bro_home(given=None):
    if given:
        return given

    result = os.environ.get("BRO_HOME")
    if result:
        return result

    cmd_result = subprocess.Popen(["which", "bro"], stdout=subprocess.PIPE,
                                  stdin=subprocess.PIPE).communicate()[0]
    if cmd_result:
        result = os.path.dirname(os.path.dirname(cmd_result))
        if result:
            return result

    raise RuntimeError("Cannot find bro")


class HttpData(object):
    # record used for information exchange with bro
    # !!!important. the record key order was important. must following bro script
    DEFINE = ("method", "host", "uri", "referrer", "user_agent",
              "req_content_type", "res_content_type", "cookie",
              "req_body_len", "resp_body_len", "status_code",
              "status_msg", "ts", "orig_ip", "orig_port", "resp_ip",
              "resp_port", "req_headers", "resp_headers", "req_body",
              "resp_body", "log_body", "is_static")

    def __init__(self, data):
        if len(data) != len(HttpData.DEFINE):
            # print len(data),data
            # print len(HttpData.DEFINE),HttpData.DEFINE
            return

        data = tuple([str(x) for x in data])
        self.method, self.host, self.uri, self.referrer, self.user_agent, self.req_content_type, self.res_content_type, \
        self.cookie, self.req_body_len, self.resp_body_len, self.status_code, self.status_msg, \
        self.ts, self.orig_ip, self.orig_port, self.resp_ip, self.resp_port, self.req_headers, self.resp_headers, self.req_body, \
        self.resp_body, self.log_body, self.is_static = data


class BroHttpDriver(Driver):
    EVENT_TOPIC = "/sniffer/events"
    CMD_TOPIC = "/sniffer/cmds"

    def __init__(self, interface, ports=None, embedded_bro=True, bro_home=None, idx=1,
                 start_port=None, bpf_filter=""):
        Driver.__init__(self)

        if ports is None:
            ports = [80, 81, 1080, 3128, 8000, 8080, 8888, 9001]
        self.embedded_bro = embedded_bro
        self.bro_home = get_bro_home(bro_home)
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.logger = settings.init_logging('bro.{}'.format(idx))
        self.ports = configcontainer.get_config("sniffer").get_string("filter.traffic.server_ports", "") or ports
        self.ports = expand_ports(self.ports)
        self.idx = idx
        self.bro_port = start_port + idx
        self.last_netstat_ts = millis_now()
        self.sub_task = None
        self.client_task = None
        self.last_update = 0
        self.filtered_clients = []
        self.encrypt_keys = []
        self.encrypt_salt = ""
        self.ep = None
        self.sub = None
        self.ss = None
        self.data_mr = None
        self.error_mr = None
        self.running = False

    def start(self):
        if self.running:
            return

        self.running = True
        self.logger.info('bro starting:{}'.format(self.running))
        # metrics should initialize in its own process
        self.data_mr = MetricsRecorder("sniffer.driver.data")
        self.error_mr = MetricsRecorder("sniffer.driver.error")
        # establish bro
        if self.embedded_bro:
            if not self.interface:
                self.add_error_metrics("invalid params")
                raise RuntimeError("null interface")

            if not self.ports:
                self.add_error_metrics("invalid params")
                raise RuntimeError("null ports")

            self.logger.info("trying to start bro driver on interface %s for ports %s", self.interface, self.ports)

            tmp_bro_file_name = os.path.join("tmp", "worker-{}-{}".format(self.interface, self.idx))
            out = file(tmp_bro_file_name, "w")
            ports_str = "".join("{}/tcp,".format(_) for _ in self.ports)
            out.close()

            executable = os.path.join(self.bro_home, "bin/bro")
            # script = os.path.join(self.bro_home, "share/bro/base/protocols/http/main.bro")
            script = os.path.join(settings.Conf_Sniffer_Path, "http.bro")
            environments = dict()
            environments["PCAP_PF_RING_CLUSTER_ID"] = "13"
            environments["PCAP_PF_RING_APPNAME"] = "bro-" + self.interface
            environments["PCAP_PF_RING_USE_CLUSTER_PER_FLOW_4_TUPLE"] = "1"

            self.logger.info('init bro, bro home is {}'.format(self.bro_home))
            self.logger.info('init bro, bro executable is {}'.format(executable))
            self.logger.info('init bro, bro interface is {}'.format(self.interface))
            self.logger.info('init bro, bro bpf filter is {}'.format(self.bpf_filter))
            self.logger.info('init bro, bro temp file is {}'.format(tmp_bro_file_name))
            self.logger.info('init bro, bro script is {}'.format(script))
            if self.bpf_filter:
                # use bpf filter
                self.sub_task = subprocess.Popen([executable, "-C", "-b", "-i", self.interface, "-f",
                                                  self.bpf_filter, tmp_bro_file_name, script], shell=False,
                                                 preexec_fn=os.setsid, stderr=sys.stderr, stdout=sys.stdout,
                                                 env=environments)
            else:
                self.sub_task = subprocess.Popen([executable, "-C", "-b", "-i", self.interface, tmp_bro_file_name,
                                                  script], shell=False, preexec_fn=os.setsid, stderr=sys.stderr,
                                                 stdout=sys.stdout, env=environments)
            atexit.register(self.stop)
            # establish client
            gevent.sleep(5)

        self.connect_bro()
        self.config_bro()
        self.client_task = gevent.spawn(self.process_input)
        self.logger.info("driver start")
        self.client_task.start()
        return

    def connect_bro(self):
        self.logger.info("connect to bro on port %s", self.bro_port)
        self.ep = broker.Endpoint()
        self.sub = self.ep.make_subscriber(BroHttpDriver.EVENT_TOPIC)
        self.ss = self.ep.make_status_subscriber(True)
        self.ep.peer("127.0.0.1", self.bro_port)
        self.logger.info("connect to bro on port 1 %s", self.bro_port)
        st = self.ss.get()
        self.logger.info("connect to bro on port 2 %s", self.bro_port)
        if not (type(st) == broker.Status and st.code() == broker.SC.PeerAdded):
            self.logger.info("connect to bro failed")
            raise RuntimeError("connect to bro failed")
        self.logger.info("connect to bro successed")

    def config_bro(self):
        self.logger.debug("sending config to bro")
        self.ep.publish(BroHttpDriver.CMD_TOPIC, broker.bro.Event("Control::net_stats_request"))
        self.ep.publish(BroHttpDriver.CMD_TOPIC,
                        broker.bro.Event("update_staticresourcesuffix", str(suffix_config.get())))
        self.ep.publish(BroHttpDriver.CMD_TOPIC,
                        broker.bro.Event("update_filteredhosts", str(filtered_hosts_config.get())))
        self.ep.publish(BroHttpDriver.CMD_TOPIC,
                        broker.bro.Event("update_filteredurls", str(filtered_urls_config.get())))
        self.ep.publish(BroHttpDriver.CMD_TOPIC,
                        broker.bro.Event("update_filteredservers", str(filtered_servers_config.get())))

    def process_httpevent(self, data):
        try:
            self.add_input_data_metrics()
            if not data.method or not data.host:
                self.add_error_metrics("null host")
                self.add_drop_data_metrics("null host")
                self.logger.error("error data method:{} or host{}".format(data.method, data.host))
                return
                # raise RuntimeError("null field")
            self.logger.debug("start process_httpevent")

            args = dict()
            args["method"] = data.method
            args["host"] = data.host
            args["uri"] = data.uri or ""
            args["uriraw"] = data.uri
            args["referer"] = data.referrer
            args["user_agent"] = data.user_agent
            args["status_code"] = data.status_code
            args["status_msg"] = data.status_msg
            args["source_ip"] = data.orig_ip
            args["source_port"] = data.orig_port.split("/")[0]
            args["dest_ip"] = data.resp_ip
            args["dest_port"] = data.resp_port.split("/")[0]
            args["req_headers"] = {}
            for header in data.req_headers.split("$$$"):
                if not header:
                    continue
                parts = header.split("@@@")
                args["req_headers"][parts[0]] = parts[1]
            args["resp_headers"] = {}
            for header in data.resp_headers.split("$$$"):
                if not header:
                    continue
                parts = header.split("@@@")
                args["resp_headers"][parts[0]] = parts[1]
            args["req_body"] = data.req_body
            args["resp_body"] = data.resp_body
            args["log_body"] = data.log_body
            args["req_body_len"] = data.req_body_len
            args["resp_body_len"] = data.resp_body_len
            args['req_content_type'] = data.req_content_type
            args['resp_content_type'] = data.res_content_type
            ts = float(data.ts)
            secs = int(ts)
            msecs = int(1000 * (ts - secs))
            args["ts_secs"] = secs
            args["ts_msecs"] = msecs

            args["debug_processing"] = False
            try:
                msg = HttpMsg(**args)
                if ":" in msg.source_ip or not msg.source_ip:
                    print data
                self.logger.debug("get msg %s", msg)
                self.put_msg(msg)
                self.add_output_data_metrics()
            except BeFilteredException as bfe:
                self.add_drop_data_metrics(bfe.type)
                return
            except Exception as err:
                self.add_drop_data_metrics(str(err))
                self.add_error_metrics("msg_parse")
                return

        except Exception as ex:
            import traceback
            self.logger.error("process_httpevent error:{}".format(traceback.print_exc()))
            self.add_drop_data_metrics("data_parse")
            self.add_error_metrics("data_parse")
            self.logger.error("error while receiving data %s", str(ex))
            self.add_dropped_msgs(1)

    def stop(self):
        self.logger.warn("bro stop...")
        if not self.running:
            self.logger.warn("bro running:{}".format(self.running))
            return

        self.running = False
        gevent.sleep(2)
        self.client_task = None

        if self.sub_task is not None:
            try:
                self.logger.warn("bro killpg({})...".format(self.sub_task.pid))
                os.killpg(self.sub_task.pid, signal.SIGTERM)
                self.logger.warn("bro killpg({}) down.".format(self.sub_task.pid))
            except Exception as ex:
                self.logger.error("fail to kill the process, %s", ex)
                traceback.print_exc()
            self.sub_task.wait()
            self.sub_task = None

        self.logger.warn("bro stop down.")

    def is_alive(self):
        current = millis_now()
        if not self.embedded_bro:
            return True

        if self.ss and self.ss.available():
            st = self.ss.get()
            if not (type(st) == broker.Status and st.code() == broker.SC.PeerAdded):
                self.logger.info("connect to bro failed")
                return False

        if current - self.last_netstat_ts > 30 * 1000:
            self.config_bro()
            self.last_netstat_ts = current

        return self.sub_task is not None and self.sub_task.poll() is None

    def process_input(self):
        while self.running:
            try:
                self.logger.debug("bro process_input:{}".format(self.running))
                if self.sub.available():
                    (t, d) = self.sub.get()
                    events = broker.bro.Event(d)
                    self.logger.debug("received {}{}".format(events.name(), events.args()))
                    for e in events.args():
                        try:
                            data = HttpData(e)
                        except:
                            self.logger.error("bro.Event to HttpData except: {}".format(traceback.print_exc()))
                        self.process_httpevent(data)

                        if not self.running:
                            self.logger.error("bro process_input stopped.")
                            break
                else:
                    self.logger.debug("bro sub not available.")
                    gevent.sleep(1)
            except:
                self.logger.error("bro process_input except: {}".format(traceback.print_exc()))
        self.logger.error("bro process_input stopped.")

    # ## For metrics
    def add_data_metrics(self, data_type, subtype=""):
        tags = {"source_type": "bro", "interface": self.interface, "type": data_type, "port": str(self.ports),
                "subtype": subtype}
        self.data_mr.record(1, tags)

    def add_input_data_metrics(self):
        return self.add_data_metrics("input")

    def add_output_data_metrics(self):
        return self.add_data_metrics("output")

    def add_drop_data_metrics(self, reason=""):
        return self.add_data_metrics("drop", reason)

    def add_error_metrics(self, data_type):
        tags = {"source_type": "bro", "interface": self.interface, "type": data_type, "port": str(self.ports)}
        self.error_mr.record(1, tags)


if __name__ == "__main__":
    driver = BroHttpDriver("eth0", "127.0.0.1:47758", start_port=8091)
    driver.start()
    driver.client_task.join()
