#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess
import os
import logging
import traceback

import gevent
import gevent.queue
import settings

from threathunter_common.metrics.metricsrecorder import MetricsRecorder
from nebula_parser.autoparser import get_current_generators

from .urltree import URLTree
from .utils import is_linux
from .bson.objectid import ObjectId
from .msg import TextMsg, HttpMsg
from .sessionmapping import *

max_body_length_config = configcontainer.get_config("sniffer").int_item("sniffer.httpmsg.max_body",
                                                                        caching=3600, default=2048)


class Main(object):

    def __init__(self, id, parser, driver, cpu=None, is_process=True):
        self.parser = parser
        self.driver = driver
        self.id = id

        self._running = False
        self._rpc_task = None
        self._events_task = None
        self._health_task = None

        self.queue = gevent.queue.Queue(maxsize=10000)
        self.cpu = cpu
        self.is_process = is_process

        self.logger = settings.init_logging("main.{}".format(self.id))

        self.error_mr = MetricsRecorder("sniffer.main.error")
        self.msg_mr = MetricsRecorder("sniffer.main.msg")
        self.event_mr = MetricsRecorder("sniffer.main.event")
        self.rpc_mr = MetricsRecorder("sniffer.main.rpc")
        self.main_mr = MetricsRecorder("sniffer.main.loop")

        self.urltree = URLTree()

    def add_error_metrics(self, data_type):
        tags = {"id": self.id, "type": data_type}
        self.error_mr.record(1, tags)

    def start(self):
        if self._running:
            return

        self.main_mr.record(1, {"id": self.id, "type": "start"})
        # cpu binding
        self.logger.info("process %s binding to cpu %s", os.getpid(), self.cpu)
        if is_linux() and self.cpu and self.is_process:
            subprocess.Popen(["taskset", "-cp", "{}".format(self.cpu), "{}".format(os.getpid())],
                             stderr=subprocess.PIPE, stdout=subprocess.PIPE).communicate()

        self._running = True

        self.logger.info("sniffer instance is starting driver")
        if self.driver:
            self.driver.start()

        self.logger.info("sniffer instance is starting rpc task")
        self._rpc_task = gevent.spawn(self.rpc_processor)
        self._rpc_task.start()

        # parse event for httpmsg
        self.logger.info("sniffer instance is starting events task")
        self._events_task = gevent.spawn(self.event_processor)
        self._events_task.start()

        self.logger.info("sniffer instance is starting healthy task")
        self._health_task = gevent.spawn(self.health_processor)
        self._health_task.start()

        self.urltree.synchronize()

    def stop(self):
        self._running = False
        self.logger.info("sniffer instance is stopping rpc task")
        self.main_mr.record(1, {"id": self.id, "type": "stop"})
        if self._rpc_task:
            self._rpc_task.kill()

        self.logger.info("sniffer instance is stopping events task")
        if self._events_task:
            self._events_task.kill()

        self.logger.info("sniffer instance is stopping healthy task")
        if self._health_task:
            self._health_task.kill()

        self.logger.info("sniffer instance is stopping driver")
        if self.driver:
            self.driver.stop()

    def close(self):
        self.stop()

    def __del__(self):
        self.stop()

    def event_processor(self):
        idle_run = 0
        while self._running:
            # no events coming
            if idle_run > 0 and idle_run % 5 == 0:
                # idle sleep for 0.5 seconds
                gevent.sleep(0.5)
                if idle_run % 100 == 0:
                    self.logger.debug("no msg in the last short time")
                    self.main_mr.record(1, {"id": self.id, "type": "idle"})
            try:
                msg = self.driver.get_msg_nowait()
            except Exception as ex:
                # no msg yet
                msg = None

            if not msg:
                idle_run += 1
                continue
            else:
                idle_run = 0
                # msg common processing
                try:
                    self.msg_mr.record(1, {"id": self.id, "type": "input"})
                    # 开始bones折叠
                    self.urltree.synchronize()
                    uri_stem = msg.uri_stem
                    page = msg.page
                    if msg.is_static:
                        # 静态页面特殊逻辑
                        new_url = msg.host + '/****.' + msg.page.rsplit('.', 1)[-1]
                        msg.uri_stem = msg.page = new_url
                    elif page == uri_stem:
                        # no normalization yet
                        new_page, new_params = self.urltree.normalize_url(page)
                        if new_page != page:
                            msg.uri_stem = new_page
                            msg.page = new_page
                            new_params = '&'.join(['%s=%s' % (k, v) for k, v in new_params.iteritems()])
                            old_params = msg.uri_query
                            if old_params:
                                new_params = old_params + '&' + new_params
                            msg.uri_query = new_params

                    # msg specific processing per customer
                    if self.parser.filter(msg):
                        self.logger.debug("filtered by customparsers")
                        self.msg_mr.record(1, {"id": self.id, "type": "drop"})
                        continue

                    self.logger.debug("msg has passed the filter")

                    events = []
                    if isinstance(msg, HttpMsg):
                        # parse 实际入口，对http信息进行处理，返回一个events（事件列表）
                        events = self.parser.get_events_from_http_msg(msg)
                    elif isinstance(msg, TextMsg):
                        events = self.parser.get_events_from_text_msg(msg)
                    else:
                        self.logger.error("fail to process this type of event")
                        self.add_error_metrics("parse failure")
                        continue

                    http_events = [e for e in events if e.name in {"HTTP_DYNAMIC", "HTTP_STATIC"}]
                    if not http_events:
                        continue

                    # 取第一个是因为所有的，客户处理模块中第一个处理函数都是extract_http_log_event()
                    http_event = http_events[0]
                    # try autoparsers
                    for g in get_current_generators():
                        result = g.parse_event(http_event, msg)
                        if result:
                            events.append(result)

                    if not events:
                        continue

                    self.msg_mr.record(1, {"id": self.id, "type": "output"})
                    self.event_mr.record(len(events), {"id": self.id, "type": "input"})

                    # this is an ugly version, need a totally new one
                    # processing id and pid
                    httpid = "0" * 24
                    for ev in events:
                        if ev.name in {"HTTP_DYNAMIC", "HTTP_STATIC"}:
                            ev.property_values["pid"] = "0" * 24
                            httpid = ev.property_values["id"]

                    for ev in events:
                        if ev.name not in {"HTTP_DYNAMIC", "HTTP_STATIC"}:
                            ev.property_values["id"] = str(ObjectId())
                            ev.property_values["pid"] = httpid

                    # "processing uid/did/sid"
                    id_dict = {
                        "uid": "",
                        "did": "",
                        "sid": "",
                    }
                    for ev in events:
                        for key in id_dict.keys():
                            if ev.property_values.get(key):
                                id_dict[key] = ev.property_values[key]
                        if ev.name == "ACCOUNT_LOGIN":
                            if 'user_name' in ev.property_values:
                                id_dict["uid"] = ev.property_values["user_name"]
                                store_user_session_mapping(id_dict["uid"], id_dict["sid"])
                        if ev.name == "ACCOUNT_REGISTRATION":
                            if 'user_name' in ev.property_values:
                                id_dict["uid"] = ev.property_values["user_name"]
                                store_user_session_mapping(id_dict["uid"], id_dict["sid"])

                    if not id_dict["uid"] or id_dict["uid"].startswith("fake"):
                        t = get_user_from_session(id_dict["sid"])
                        if t:
                            id_dict["uid"] = t

                    self.logger.debug("get id for this batch of events %s", id_dict)
                    for ev in events:
                        ev.property_values.update(id_dict)

                    _max_length = max_body_length_config.get()
                    for ev in events:
                        # body should not be too long
                        if "s_body" in ev.property_values:
                            ev.property_values["s_body"] = ev.property_values["s_body"][:_max_length]
                        if "c_body" in ev.property_values:
                            ev.property_values["c_body"] = ev.property_values["c_body"][:_max_length]

                    # end of the ugly code
                    for ev in events:
                        self.queue.put_nowait(ev)
                    self.event_mr.record(len(events), {"id": self.id, "type": "output"})
                except:
                    # todo add metrics
                    self.add_error_metrics("main process failure")
                    self.msg_mr.record(1, {"id": self.id, "type": "drop"})
                    self.logger.error("fail to process, error %s",traceback.format_exc())

    def health_processor(self):
        while self._running:
            if self.driver and not self.driver.is_alive():
                self._running = False

            gevent.sleep(5)

    def rpc_processor(self):
        mode = configcontainer.get_config("sniffer").get_string("sniffer.servicemode", "redis")
        if mode == "redis":
            import redisserviceclient
            http_client = redisserviceclient.get_httplog_rpc_client()
            misc_client = redisserviceclient.get_misclog_rpc_client()
        elif mode == "rabbitmq":
            import rabbitmqserviceclient
            amqp_url = configcontainer.get_config("sniffer").get_string("sniffer.amqp_url", "")
            http_client = rabbitmqserviceclient.get_httplog_rpc_client(amqp_url)
            misc_client = rabbitmqserviceclient.get_misclog_rpc_client(amqp_url)
        else:
            self.add_error_metrics("invalid service")
            raise RuntimeError("invalid service mode")

        http_client.start()
        misc_client.start()
        idle_run = 0
        events_sent = 0
        r = 0
        event = None
        while self._running:
            r += 1
            try:
                events_sent = 0
                event = self.queue.get_nowait()
                self.rpc_mr.record(1, {"id": self.id, "type": "input", "mode": mode, "name": event.name})
                if event.name == "HTTP_DYNAMIC" or event.name == "HTTP_STATIC":
                    if event.property_values["is_static"]:
                        # remove redundant values
                        event.property_values["s_body"] = ""
                        event.property_values["c_body"] = ""
                        event.property_values["cookie"] = ""
                    event.key = event.property_values["c_ip"]
                    http_client.send(event, event.key, False)
                    self.logger.debug("sending an http event on key: {}".format(event.key))
                    self.rpc_mr.record(1, {"id": self.id, "type": "output", "mode": mode, "name": event.name})
                else:
                    misc_client.send(event, event.key, False)
                    self.logger.debug("sending an {} event on key {}".format(event.name, event.key))
                    self.rpc_mr.record(1, {"id": self.id, "type": "output", "mode": mode, "name": event.name})
                events_sent = 1
                event = None
            except gevent.queue.Empty:
                pass
            except Exception as err:
                import traceback
                traceback.print_exc()
                self.add_error_metrics("send event")
                self.rpc_mr.record(1, {"id": self.id, "type": "error", "mode": mode,
                                       "name": event.name if event else ""})
                self.logger.error("fail to send event, error %s", err)
            finally:
                # sleep while idle
                if not events_sent:
                    idle_run += 1
                    idle_run = min(idle_run, 5)
                    gevent.sleep(0.1 * idle_run)
                else:
                    idle_run = 0
