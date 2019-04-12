#!/usr/bin/env python
# -*- coding: utf-8 -*-

from gevent.monkey import patch_all

patch_all()

import redis
import logging
import json

from threathunter_common.metrics.metricsrecorder import MetricsRecorder

from ..drivers.driver import Driver
from ..msg import HttpMsg
from ..befilteredexception import BeFilteredException


class RedisListDriver(Driver):
    def __init__(self, host, port, password="", max_count=-1):
        Driver.__init__(self, "redislist")
        self.port = port
        self.host = host
        self.password = password
        self.max_count = max_count

        self.data_mr = None
        self.error_mr = None
        self.running = False

    # ## For metrics
    def add_data_metrics(self, data_type, subtype=""):
        tags = {"source_type": "redislist", "source": "redis", "type": data_type, "port": self.port, "subtype": subtype}
        self.data_mr.record(1, tags)

    def add_input_data_metrics(self):
        return self.add_data_metrics("input")

    def add_output_data_metrics(self):
        return self.add_data_metrics("output")

    def add_drop_data_metrics(self, reason=""):
        return self.add_data_metrics("drop", reason)

    def add_error_metrics(self, data_type, subtype=""):
        tags = {"source_type": "redislist", "source": "redis", "type": data_type, "port": self.port, "subtype": subtype}
        self.error_mr.record(1, tags)

    def start(self):
        self.logger.info("start redis list driver")
        self.running = True
        self.data_mr = MetricsRecorder("sniffer.driver.data")
        self.error_mr = MetricsRecorder("sniffer.driver.error")
        task = gevent.spawn(self.redis_loop)

    def stop(self):
        self.running = False

    def redis_loop(self):
        r = redis.Redis(host=self.host, port=self.port, password=self.password)
        total_count = 0
        idle_count = 0

        while self.running:
            p = r.pipeline()
            p.lrange("traffic_records", 0, 100)
            p.ltrim("traffic_records", 100, -1)
            result = p.execute()
            if result and result[0]:
                records = result[0]
            else:
                records = []

            if records:
                idle_count = 0
            else:
                idle_count += 1
            if idle_count > 5:
                # no data available
                gevent.sleep(0.5)

            for record in records:
                try:
                    self.process_record(record)
                except:
                    pass

            total_count += len(records)
            if 0 < self.max_count < total_count:
                break

    def process_record(self, data):
        try:
            data = json.loads(data)
            self.add_input_data_metrics()
            if not data["method"] or not data["host"]:
                self.add_error_metrics("null host")
                self.add_drop_data_metrics("null host")
                return
                # raise RuntimeError("null field")

            args = dict()
            args["method"] = data["method"]
            args["host"] = data["host"]
            args["uri"] = data["uri"] or ""
            args["uriraw"] = data["uri"]
            args["referer"] = data["referrer"]
            args["user_agent"] = data["user_agent"]
            args["status_code"] = data["status_code"]
            args["status_msg"] = data['status_msg']
            args["source_ip"] = data['orig_ip']
            args["source_port"] = data['orig_port']
            args["dest_ip"] = data['resp_ip']
            args["dest_port"] = data['resp_port']
            args["req_headers"] = {}
            for header in data['req_headers'].split("$$$"):
                if not header:
                    continue
                parts = header.split("@@@")
                args["req_headers"][parts[0]] = parts[1]
            args["resp_headers"] = {}
            for header in data['resp_headers'].split("$$$"):
                if not header:
                    continue
                parts = header.split("@@@")
                args["resp_headers"][parts[0]] = parts[1]
            args["req_body"] = data['req_body']
            args["resp_body"] = data['resp_body']
            args["log_body"] = data['log_body']
            args["req_body_len"] = data['req_body_len']
            args["resp_body_len"] = data['resp_body_len']
            args['req_content_type'] = data['req_content_type']
            args['resp_content_type'] = data['res_content_type']
            ts = data['ts']
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
            traceback.print_exc()
            self.add_drop_data_metrics("data_parse")
            self.add_error_metrics("data_parse")
            self.logger.error("error while receiving data %s", str(ex))
            self.add_dropped_msgs(1)

    def is_alive(self):
        return True


if __name__ == "__main__":
    s = RedisListDriver("localhost", 6379, "", -1)
    s.start()
    import gevent

    gevent.sleep(5)
