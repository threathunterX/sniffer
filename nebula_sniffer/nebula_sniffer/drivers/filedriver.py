#!/usr/bin/env python
# -*- coding: utf-8 -*-

import gevent
import os.path
import logging
import sys
from ..drivers.driver import Driver
from ..msg import TextMsg

logger = logging.getLogger("filedriver")


class FileStatsRecorder(object):

    def __init__(self, fn):
        self.fn = fn

    def load_record_stat(self):
        invalid_return = 0, 0

        if not os.path.exists(self.fn):
            return invalid_return

        if not os.path.isfile(self.fn):
            return invalid_return

        try:
            with open(self.fn, "r") as f:
                line = f.readline()
                if not line:
                    return invalid_return
                else:
                    ino, cursor = line.split(" ")[:2]
                    return int(ino), int(cursor)
        except Exception as err:
            logger.error(err)
            return invalid_return

    def put_record_stat(self, ino, cursor):
        try:
            with open(self.fn, "w") as f:
                print >> f, "{} {}".format(int(ino), cursor)
        except Exception as err:
            logger.error(err)


class FileReader(object):
    def __init__(self, data_fn, stats_fn, cb):
        self.data_fn = data_fn
        self.stats_fn = stats_fn
        self.recorder = FileStatsRecorder(stats_fn)
        self.cb = cb
        self.running = False
        self.task = None

    def start(self):
        self.running = True
        self.task = gevent.spawn(self.bg_task)

    def stop(self):
        self.running = False
        if self.task:
            self.task.join()
            self.task = None

    def bg_task(self):
        while self.running:
            try:
                self.deal_with_file()
            finally:
                sys.stdout.flush()
                gevent.sleep(10)

    def deal_with_file(self):
        if not os.path.exists(self.data_fn):
            return

        if not os.path.isfile(self.data_fn):
            return

        ino = os.stat(self.data_fn).st_ino

        old_ino, old_cursor = self.recorder.load_record_stat()
        if old_ino != ino:
            cursor = 0
        else:
            cursor = old_cursor

        try:
            with open(self.data_fn, "r") as input_text:
                input_text.seek(cursor)
                while True:
                    line = input_text.readline()
                    if line:
                        cursor = input_text.tell()
                        self.cb(line)
                    else:
                        return
        finally:
            self.recorder.put_record_stat(ino, cursor)


class FileDriver(Driver):

    def __init__(self, data_fn, record_fn=None):
        Driver.__init__(self, "file.{}".format(self.data_fn))
        if not data_fn:
            raise RuntimeError("invalid log file")

        self.data_fn = data_fn

        if not record_fn:
            record_fn = os.path.join(os.path.dirname(data_fn), "_record")
        self.record_fn = record_fn

        self.fr = FileReader(self.data_fn, self.record_fn, self._recv_msg_fn_in)

    def _recv_msg_fn_in(self, msg):
        if not msg:
            return

        print msg
        self.put_msg(TextMsg(msg))

    def start(self):
        self.fr.start()

    def stop(self):
        self.fr.stop()

    def is_alive(self):
        return True


if __name__ == "__main__":
    import os

    print os.getcwd()
    d = FileDriver("test_data", "test_record")
    d.start()
    gevent.sleep(500)
    pass
