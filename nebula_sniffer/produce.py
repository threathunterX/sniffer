#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
#————————————————————————————————————————————————————
# FileName: produce.py
# Version: 0.0.1
# Author : Rancho
# Email:
# LastChange: 12/25/2018
# Desc:
# History:
#————————————————————————————————————————————————————
"""
import os
import time
import traceback

import gevent
import json
from json import loads
from json import dumps
import requests
from requests import post
from requests import get
from requests import put
from requests import delete
import settings

logger = settings.init_logging('nebula.produce')


class RequestsData(object):
    def __init__(self, url, data, cookies, method='get'):
        self.data = data
        self.url = url
        self.cookies = cookies
        self.method = method

    def request(self):
        m = dict(
            get=get,
            put=put,
            post=post,
            delete=delete,
        )
        method = m[self.method]
        header = {
            "connection": "close",
            "content-type": 'application/json',
        }
        response = None
        try:
            if self.method in ['get', 'delete']:
                response = method(self.url, params=self.data, cookies=self.cookies, timeout=10,
                                  headers=header)
            elif self.method in ['post', 'put']:
                data = dumps(self.data, ensure_ascii=False).encode('utf8')
                response = method(self.url, data=data, timeout=8, headers=header, cookies=self.cookies)
            else:
                raise ValueError
        except Exception as e:
            logger.error("produce request error:", e)

        finally:
            return response


def write_file(py_name, version, content):
    version = int(version)
    old = py_name + "_" + str(version - 1) + '.py'
    new = py_name + "_" + str(version) + '.py'
    found = os.path.exists(old)
    if found:
        os.rename(old, new)
    else:
        pass

    with open(new, 'w') as f:
        f.write(content)
    return


def py_from_address(path):
    root = ''
    files = []
    for root, dirs, file in os.walk(path):
        files.extend(file)
        root = root
    return (root, files)


def delete_pyc(data):
    r = []
    for e in data:
        if (e == '__init__.py') or ('pyc' in e):
            pass
        else:
            r.append(e)
    return r


def name_from_file(files):
    r = []
    for f in files:
        n = f.split('_')
        if len(n) > 1:
            name = n[0]
            version = n[1][0: -3]
            r.append((name, version))
        else:
            pass
    return r


def nebula_strategy_get(url, py_name):
    data = dict(
        strategy=py_name,
    )
    r = RequestsData(url, data, {}, 'get')
    request = r.request()
    return request


def all_py(url):
    from complexconfig.configcontainer import configcontainer
    sniffer_config = configcontainer.get_config("sniffer")
    events_url = sniffer_config.get_string('sniffer.web_config.host', 'http://127.0.0.1:9001/nebula/events')
    events_url = events_url + '/nebula/events'
    r = requests.get(events_url)
    t = r.json()
    py_name_all = [e.get('name') for e in t.get('values', [])]
    py_content_all = []
    for p in py_name_all:
        request = nebula_strategy_get(url, p)
        if request is not None:
            if request.status_code == 200:
                j = request.json()
                py_content_all.append(j)
            else:
                pass
        else:
            pass
    return py_content_all


def delete_not_in_online_event(files, online_events, py_path):
    for file in files:
        if file.endswith(".pyc"):
            continue
        else:
            event_name = "_".join(file.split("_")[:-1])
            if event_name not in online_events:
                os.remove(os.path.join(py_path, file))


def produce(url):
    py_path = './nebula_sniffer/customparsers/lib/'
    try:
        data = all_py(url)
        # 获取已有py文件，获取在线事件，如果py文件不在在线事件中则进行删除
        (root, files) = py_from_address(py_path)
        online_events = [d['py_name'] for d in data]
        delete_not_in_online_event(files, online_events, py_path)

        for d in data:
            version = d['py_version']
            # (root, files) = py_from_address(debug_py_path)
            (root, files) = py_from_address(py_path)
            file = delete_pyc(files)

            # 判断 d name 在不在 文件中 如果在
            file_names_version = name_from_file(file)
            name = d['py_name']
            path = py_path + name
            # path = debug_py_path + name
            write = False

            for f in file_names_version:
                if name == f[0]:
                    if version == f[1]:
                        # 判断版本号对不对 对 不变更
                        write = True
                        # pass
                    else:
                        # 版本号不对, 覆写
                        write_file(path, version, d['py_content'])
                        write = True
                else:
                    pass
            # 不在文件中 直接写文件
            if not write:
                write_file(path, version, d['py_content'])
            else:
                pass

    except:
        logger.error('produce load error: {}'.format(traceback.format_exc()))

    finally:
        logger.info('produce load complete')


class Produce(object):
    sec = 60
    running = True
    task = None
    logger = None

    @staticmethod
    def start():
        Produce.task = gevent.spawn(Produce.__run)
        logger.info('produce started')

    @staticmethod
    def stop():
        logger.info('produce exiting...')
        Produce.running = False
        Produce.task.join()
        logger.info('produce exited')

    @staticmethod
    def __run():
        timer = 0
        from complexconfig.configcontainer import configcontainer
        sniffer_config = configcontainer.get_config("sniffer")
        while Produce.running:
            if timer < Produce.sec:
                gevent.sleep(1)
                timer += 1
            else:
                url = sniffer_config.get_string('sniffer.web_config.produce_url',
                                                'http://127.0.0.1:9001/nebula/NebulaStrategy')
                produce(url)
                timer = 0


if __name__ == '__main__':
    Produce.start()
    gevent.sleep(10)
    Produce.stop()
