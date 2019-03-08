#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Logstash server that receives information from filebeats
"""
import sys
import json
import signal
import struct
import socket
import zlib
import gevent

from gevent.server import StreamServer


class LogStashSession(object):
    """
    Session for one logstaash data connection
    """

    START = 0  # 初始状态
    WINDOW_READEY = 1  # 已经收到window header
    DATA_HEADER_READY = 2  # 已经接收到data header, 需要接收数据
    PAYLOAD_LENGTH_READY = 3  # 已经收到了payload length
    COMPRESS_HEADER_READY = 4  # 已经收到了压缩头

    def __init__(self, client, msg_callback):
        self.client = client
        self.client_address = '%s:%s' % client.getpeername()[:2]
        self.msg_callback = msg_callback

        # 解析出来的数据
        self.window_size = 0
        self.sequence = 0
        self.payload_length = 0
        self.buffer = ""
        self.current_offset = 0
        self.buffer_length = 0
        self.compress_data_length = 0

        # 状态机需要信息
        self.next_state = LogStashSession.START
        # 每个状态下，下一步需要执行的方法，以及需要的字节数
        self.state_table = {
            LogStashSession.START: (lambda: 6, self.resolve_window),
            LogStashSession.WINDOW_READEY: (lambda: 6, self.resolve_data_header),
            LogStashSession.DATA_HEADER_READY: (lambda: 4, self.resolve_payload_length),
            LogStashSession.PAYLOAD_LENGTH_READY: (lambda: self.payload_length, self.resolve_payload),
            LogStashSession.COMPRESS_HEADER_READY: (lambda: self.compress_data_length, self.resolve_compress_payload),
        }

    def session_run(self):
        while True:
            try:
                data = self.client.recv(1024)
                if not data:
                    print 'finish'
                    break

                self.update_data(data)
            except socket.error:
                break
            except RuntimeError as err:
                break

    def acknowledge(self):
        ack_message = struct.pack('!ccI', '2', 'A', self.window_size)
        if self.client:
            self.client.sendall(ack_message)

    def update_data(self, data):
        self.buffer = self.buffer + data
        self.buffer_length += len(data)
        self.run_state_machine()

    def reset_state_machine(self):
        """
        初始化设置
        :return:
        """

        # 解析数据重置
        self.window_size = 0
        self.sequence = 0
        self.payload_length = 0
        self.compress_data_length = 0

        # 初始化状态
        self.next_state = LogStashSession.START

        # 处理buffer
        self.buffer = self.buffer[self.current_offset:]
        self.buffer_length -= self.current_offset
        self.current_offset = 0

    def run_state_machine(self):
        """
        处理状态转换
        """

        if not self.buffer:
            return

        while True:
            # 数据已经足够，取下一个状态的处理
            needed_bytes_function, next_function = self.state_table[self.next_state]
            needed_bytes = needed_bytes_function()
            if (self.buffer_length - self.current_offset) < needed_bytes:
                # data is not enough
                break

            self.next_state = next_function()
            self.current_offset += needed_bytes

    def resolve_window(self):
        """
        处理window
        :return:
        """

        version, data_type, window_size = struct.unpack_from('!ccI', self.buffer, self.current_offset)
        if version != '2':
            raise RuntimeError('only support version 2')
        if data_type != 'W':
            raise RuntimeError('invalid window header')
        self.window_size = window_size
        return LogStashSession.WINDOW_READEY

    def resolve_data_header(self):

        version, data_type, sequence = struct.unpack_from("!ccI", self.buffer, self.current_offset)
        if version != '2':
            raise RuntimeError('only support version 2')
        if data_type == 'J':
            # ordinary data
            self.sequence = sequence
            return LogStashSession.DATA_HEADER_READY
        elif data_type == 'C':
            # compress data
            self.sequence = 0
            self.compress_data_length = sequence
            return LogStashSession.COMPRESS_HEADER_READY
        else:
            raise RuntimeError('invalid data type')

    def resolve_payload_length(self):
        length, = struct.unpack_from("!I", self.buffer, self.current_offset)
        self.payload_length = length
        return LogStashSession.PAYLOAD_LENGTH_READY

    def resolve_payload(self):
        msg = self.buffer[self.current_offset:(self.current_offset + self.payload_length)]
        msg = json.loads(msg)
        msg = msg['message']
        if self.msg_callback:
            self.msg_callback(msg, self.client_address)

        if self.sequence == self.window_size:
            # already last one
            self.acknowledge()
            self.reset_state_machine()
            return LogStashSession.START
        else:
            # 开始下一条日志读取
            self.payload_length = 0
            return LogStashSession.WINDOW_READEY

    def resolve_compress_payload(self):
        msg = self.buffer[self.current_offset:(self.current_offset + self.compress_data_length)]
        msg = zlib.decompress(msg)
        # 将msg插回去
        insert_position = self.current_offset + self.compress_data_length
        self.buffer = self.buffer[:insert_position] + msg + self.buffer[insert_position:]
        self.buffer_length += len(msg)
        return LogStashSession.WINDOW_READEY


class LogStashServer(StreamServer):

    def __init__(self, msg_callback, listener, **kwargs):
        super(LogStashServer, self).__init__(listener, **kwargs)
        self.reuse_addr = 1
        self.msg_callback = msg_callback

    def handle(self, source, address):
        session = LogStashSession(source, self.msg_callback)
        log_task = gevent.spawn(session.session_run)
        log_task.join()

    def start_running(self):
        gevent.signal(signal.SIGTERM, self.close)
        gevent.signal(signal.SIGINT, self.close)
        self.start()

    def new_connection(self):
        pass

    def close(self):
        if self.closed:
            sys.exit('Multiple exit signals received - aborting.')
        else:
            StreamServer.close(self)


if __name__ == '__main__':
    def print_msg(msg):
        print msg


    l = LogStashServer(print_msg, ('0.0.0.0', 5044), )
    l.start_running()
    gevent.wait()
