#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
from kafka import KafkaConsumer
from threathunter_common.util import run_in_thread
from .driver import Driver
from ..msg import HttpMsg
from ..befilteredexception import BeFilteredException
from settings import init_logging
import traceback

__author__ = "nebula"

class KafkaDriver(Driver):
    def __init__(self, topics, **config):
        Driver.__init__(self, "kafka")
        self.consumer = None
        self.topics = topics
        self.config = config or dict()
        self.config["enable_auto_commit"] = True
        self.bg_task = None
        self.count = 0

    def _process_msg(self, msg):
        try:
            if not msg:
                return
            else:
                self.count += 1

            # 解析HTTP DATA
            # 默认JSon格式
            # 这里使用bro抓取的数据格式进行测试
            # 其他格式需要自己做处理进行解析，原则上数据越详细越好，最好下面示例里所有字段都能抓取到
            # 但有的场景可能无法获取到所有字段信息
            # 比如nginx log无法获取respone  body等详细信息, 需要使用nginx+lua方案
            '''
            #HTTP DATA
            {
                "resp_port": "9001/tcp",
                "status_code": "200",
                "resp_ip": "172.18.16.169",
                "resp_headers": "$$$SERVER@@@openresty$$$DATE@@@Fri, 12 Apr 2019 03:07:24 GMT$$$CONTENT-TYPE@@@application/json; charset=UTF-8$$$TRANSFER-ENCODING@@@chunked$$$CONNECTION@@@close$$$ACCESS-CONTROL-ALLOW-ORIGIN@@@*$$$ACCESS-CONTROL-ALLOW-METHODS@@@GET, POST, DELETE, PUT, OPTIONS, TRACE, HEAD, PATCH$$$ACCESS-CONTROL-ALLOW-HEADERS@@@Content-Type$$$ACCESS-CONTROL-ALLOW-CREDENTIALS@@@true$$$CONTENT-ENCODING@@@gzip",
                "log_body": "False",
                "resp_body_len": "98",
                "ts": "0.109587907791",
                "resp_body": "{\"values\":{\"global__visit_dynamic_count__1h__slot\":{\"value\":33,\"key\":1555038444669}},\"status\":200}",
                "req_content_type": "application/json",
                "req_headers": "$$$HOST@@@112.74.58.210:9001$$$CONNECTION@@@keep-alive$$$CONTENT-LENGTH@@@102$$$ACCEPT@@@application/json$$$ORIGIN@@@http://112.74.58.210:9001$$$URL@@@POST: platform/stats/slot/query$$$PERFMARK@@@POST: platform/stats/slot/query$$$USER-AGENT@@@Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36$$$CONTENT-TYPE@@@application/json$$$REFERER@@@http://112.74.58.210:9001/$$$ACCEPT-ENCODING@@@gzip, deflate$$$ACCEPT-LANGUAGE@@@zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,und;q=0.6$$$COOKIE@@@group_id=\"2|1:0|10:1554361612|8:group_id|4:Mg==|f4bbd462041c580a7471bd7f756c9e49c1fa2488162367cea83cc65e0c404682\"; user_id=\"2|1:0|10:1554361612|7:user_id|4:Mg==|a214dedaa5198d029d92d36a3a20dce99b40fe9532385e6267c99cb420787f3d\"; user=\"2|1:0|10:1554361612|4:user|24:dGhyZWF0aHVudGVyX3Rlc3Q=|8b440b29fd7c7d7fa6b7d2d61fa86cbc8edc7d48975c11595cb8c36b557c7e7f\"; auth=\"2|1:0|10:1554361612|4:auth|44:OTljODU0NjFhYWQyMGE4YWRiMGViMjU1MDZkYzE1MTU=|de39516f534446669bf4d4c702db7feb69161a89ff8bcb5c5837d8b10a9e35ee\"",
                "method": "POST",
                "orig_ip": "116.24.67.182",
                "req_body": "{\"dimension\":\"global\",\"variables\":[\"global__visit_dynamic_count__1h__slot\"],\"timestamp\":1555038000000}",
                "req_body_len": "102",
                "orig_port": "17239/tcp",
                "host": "112.74.58.210",
                "res_content_type": "application/json; charset=UTF-8",
                "cookie": "group_id=\"2|1:0|10:1554361612|8:group_id|4:Mg==|f4bbd462041c580a7471bd7f756c9e49c1fa2488162367cea83cc65e0c404682\"; user_id=\"2|1:0|10:1554361612|7:user_id|4:Mg==|a214dedaa5198d029d92d36a3a20dce99b40fe9532385e6267c99cb420787f3d\"; user=\"2|1:0|10:1554361612|4:user|24:dGhyZWF0aHVudGVyX3Rlc3Q=|8b440b29fd7c7d7fa6b7d2d61fa86cbc8edc7d48975c11595cb8c36b557c7e7f\"; auth=\"2|1:0|10:1554361612|4:auth|44:OTljODU0NjFhYWQyMGE4YWRiMGViMjU1MDZkYzE1MTU=|de39516f534446669bf4d4c702db7feb69161a89ff8bcb5c5837d8b10a9e35ee\"",
                "is_static": "False",
                "referrer": "http://112.74.58.210:9001/",
                "status_msg": "OK",
                "uri": "/platform/stats/slot/query",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36"
            }
            '''
            data = json.loads(msg)

            #对HTTP DATA进行处理并格式化为HttpMsg
            args = dict()
            args["_id"] = self.count
            args["source_ip"] = data.get("orig_ip", "")
            # 提取端口
            args["source_port"] = data.get("orig_port", "0").split("/")[0]
            args["dest_ip"] = data.get("resp_ip", "")
            # 提取端口
            args["dest_port"] = data.get("resp_port", "0").split("/")[0]
            args["method"] = data.get("method", "")
            args["host"] = data.get("host", "")
            args["uri"] = data.get("uri", "")
            args["user_agent"] = data.get("user_agent", "")
            args["status_msg"] = data.get("status_msg", "")
            args["status_code"] = data.get("status_code", "")

            # 提取request header信息
            args["req_headers"] = {}
            for header in data.get("req_headers", "").split("$$$"):
                if not header:
                    continue
                parts = header.split("@@@")
                args["req_headers"][parts[0]] = parts[1]

            # 提取resp header信息
            args["resp_headers"] = {}
            for header in data.get("resp_headers", "").split("$$$"):
                if not header:
                    continue
                parts = header.split("@@@")
                args["resp_headers"][parts[0]] = parts[1]

            # 用时
            ts = float(data.get("ts", "0"))
            secs = int(ts)
            msecs = int(1000*(ts-secs))
            args["ts_secs"] = secs
            args["ts_msecs"] = msecs

            args["req_body_len"] = data.get("req_body_len", "")
            args["resp_body_len"] = data.get("resp_body_len", "")
            args["req_content_type"] = data.get("req_content_type", "")
            args["resp_content_type"] = data.get("resp_content_type", "")
            args["referer"] = data.get("referer", "")
            args["req_body"] = data.get("req_body", "")
            args["resp_body"] = data.get("resp_body", "")
            args["log_body"] = data.get("log_body", "")

            args["debug_processing"] = False

            self.logger.debug("get http data from kafka: %s", args)

            try:
                #格式化为HttpMsg
                new_msg = HttpMsg.from_dict(args)
                #new_msg = HttpMsg.from_json(msg)
            except BeFilteredException as bfe:
                return
            except Exception as err:
                self.logger.error("fail to parse: %s, error: %s, traceback: %s", args, err, traceback.format_exc())
                #self.logger.error("fail to parse: %s, error: %s, traceback: %s", msg, err, traceback.format_exc())
                return

            self.logger.debug("get http msg from kafka: %s", new_msg)
            self.put_msg(new_msg)

            return new_msg
        except Exception as ex:
            self.logger.error("fail to parse kafka data: %s", ex)

    def start(self):
        self.consumer = KafkaConsumer(self.topics,**self.config)
        self.bg_task = run_in_thread(self.bg_processing)

    def bg_processing(self):
        if not self.consumer:
            return
        while True:
            for m in self.consumer:
                self._process_msg(m.value)

    def is_alive(self):
        return self.bg_task and self.bg_task.isAlive()

    def stop(self):
        pass
