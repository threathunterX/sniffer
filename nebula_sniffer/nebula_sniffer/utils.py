# -*- coding: utf-8 -*-

import json
import Cookie
import urlparse
from os import path as opath
import subprocess
import os
import jinja2


def is_linux():
    uname = subprocess.Popen(["uname"], shell=False, preexec_fn=os.setsid, stderr=subprocess.PIPE,
                             stdout=subprocess.PIPE)
    return "linux" == uname.communicate()[0].lower().strip()


class Storage(dict):
    """
    A Storage object is like a dictionary except `obj.foo` can be used
    in addition to `obj['foo']`.

        >>> o = storage(a=1)
        >>> o.a
        1
        >>> o['a']
        1
        >>> o.a = 2
        >>> o['a']
        2
        >>> del o.a
        >>> o.a
        Traceback (most recent call last):
            ...
        AttributeError: 'a'

    """

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError, k:
            raise AttributeError(k)

    def __setattr__(self, key, value):
        self[key] = value

    def __delattr__(self, key):
        try:
            del self[key]
        except KeyError, k:
            raise AttributeError(k)

    def __repr__(self):
        return '<Storage ' + dict.__repr__(self) + '>'


def render(template_path, context):
    """
    Assuming a template at /some/path/my_tpl.html, containing:

    Hello {{ firstname }} {{ lastname }}!

    >> context = {
    'firstname': 'John',
    'lastname': 'Doe'
    }
    >> result = render('/some/path/my_tpl.html', context)
    >> print(result)
    Hello John Doe!
    """

    path, filename = opath.split(template_path)
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(path or './')
    ).get_template(filename).render(context)


COMMON_SESSIONIDS = {"sessionid", "JSESSIONID", "PHPSESSID", "ASPSESSIONID", "ASP.NET_SessionId", "CGISESSID"}


class HttpSessionUtils(object):
    U""" 从http请求/响应中获取sessionid"""

    # TODO parse the bare http headers and body
    def __init__(self, session_keys, uri, cookie, body):
        self.session_keys = session_keys
        self.uri = uri
        self.body = body
        self.cookie = cookie

    def get_sessionid(self):
        u"""
        按如下顺去取sessionid, 取到为止. Cookie/uri/body.
        """
        data = self.get_sessionid_from_cookie()
        if data is not None:
            return data

        data = self.get_sessionid_from_uri()
        if data is not None:
            return data

        data = self.get_sessionid_from_body()
        if data is not None:
            return data

        return None

    def get_sessionid_from_cookie(self):
        cookie = Cookie.SimpleCookie()
        if self.cookie:
            cookie.load(self.cookie)

        cookie = {k: [v.value] for k, v in cookie.items()}

        return self._get_session_index(cookie)

    def get_sessionid_from_uri(self):
        url_data = urlparse.urlparse(self.uri)
        query_data = urlparse.parse_qs(url_data.query)

        return self._get_session_index(query_data)

    def get_sessionid_from_body(self):
        u"""
        先尝试用json解析，如果失败。则直接使用form-encode解析
        """
        try:
            data = self._json_decode_httpbody()
        except ValueError:
            data = self._form_decode_httpbody()

        return self._get_session_index(data)

    def _form_decode_httpbody(self):
        return urlparse.parse_qs(self.body)

    def _json_decode_httpbody(self):
        return json.loads(self.body)

    def _get_session_index(self, data):
        # check user defined keys
        if not isinstance(data, dict):
            return ""
        d = {k.upper(): v for k, v in data.items()}
        for key in self.session_keys:
            sessionids = d.get(key.upper())
            if sessionids and len(sessionids) >= 1:
                return sessionids[0]

        # check common keys
        for key in COMMON_SESSIONIDS:
            sessionids = d.get(key.upper())
            if sessionids and len(sessionids) >= 1:
                return sessionids[0]

        return None


def get_sessionid(bro_data, session_keys=None):
    u"""
    获取sessionid, 快捷函数
    """

    if session_keys is None:
        session_keys = dict()
    cookie = bro_data.cookie
    body = bro_data.req_body
    session_utils = HttpSessionUtils(session_keys=session_keys,
                                     uri=bro_data.uri,
                                     cookie=cookie,
                                     body=body)
    return session_utils.get_sessionid()


def expand_ports(raw_ports):
    """
    Expant ports from config test to a list.

    The config may be 1080,2000-20005,3000; we need to build a list as [1080, 2000, 2001, 2002, 2003, 2004, 2005, 3000]
    :param raw_ports:
    :return:
    """
    if not isinstance(raw_ports, list):
        if isinstance(raw_ports, (str, unicode)):
            raw_ports = raw_ports.split(",")
        else:
            raise RuntimeError("invalid ports config")
    ports = [str(p) for p in raw_ports]

    # first add the single port
    new_ports = [int(p) for p in ports if "-" not in p]

    # second add the consecutive ports
    for p in ports:
        if "-" in p:
            start, end = p.split("-")[:2]
            new_ports.extend(range(int(start), int(end) + 1))

    return new_ports
