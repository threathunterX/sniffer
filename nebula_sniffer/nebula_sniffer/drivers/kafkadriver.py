#!/usr/bin/env python
# -*- coding: utf-8 -*-
from kafka import KafkaConsumer
from threathunter_common.util import run_in_thread
from .driver import Driver
from ..msg import TextMsg

__author__ = 'lw'


class KafkaDriver(Driver):
    def __init__(self, topics, **config):
        Driver.__init__(self)
        self.consumer = None
        self.topics = list(topics)
        self.config = config or dict()
        self.config["auto_commit_enable"] = True
        self.bg_task = None

    def _process_msg(self, msg):
        try:
            if not msg:
                return
            new_msg = TextMsg(msg, False)
            self.put_msg(new_msg)
        except Exception as ex:
            self.add_dropped_msgs(1)

    def start(self):
        self.consumer = KafkaConsumer(*self.topics, **self.config)
        self.bg_task = run_in_thread(self.bg_processing)

    def bg_processing(self):
        if not self.consumer:
            return
        while True:
            for m in self.consumer.fetch_messages():
                self._process_msg(m)
                self.consumer.task_done(m)

    def is_alive(self):
        return self.bg_task and self.bg_task.isAlive()

    def stop(self):
        pass
