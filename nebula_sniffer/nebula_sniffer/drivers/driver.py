#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import gevent
import gevent.queue

__author__ = "nebula"

logger = logging.getLogger("sniffer.driver")


class Driver(object):
    def __init__(self, maxsize=1000):
        # internal msg queue
        self.queue = gevent.queue.Queue(maxsize=maxsize)

        # # of dropped msgs by driver
        self.dropped_msgs = 0

        # # of the recent consecutive errors due to queue full
        # TODO thread safe
        self.full_error_count = 0

    def start(self):
        raise NotImplementedError()

    def stop(self):
        raise NotImplementedError()

    def is_alive(self):
        raise NotImplementedError()

    def put_msg(self, msg):
        try:
            self.queue.put_nowait(msg)
            self.full_error_count = 0
        except gevent.queue.Full as err:
            self.dropped_msgs += 1
            self.full_error_count += 1
            if self.full_error_count <= 3 or self.full_error_count % 10000 == 0:
                logger.error("dropping msg due to queue full, {} msgs dropped recently".format(self.full_error_count))

    def get_msg_nowait(self):
        result = self.queue.get_nowait()
        return result

    def add_dropped_msgs(self, count):
        self.dropped_msgs += count

    def dump_dropped_msgs(self):
        result = self.dropped_msgs
        self.dropped_msgs = 0
        return result

    def __del__(self):
        self.stop()
