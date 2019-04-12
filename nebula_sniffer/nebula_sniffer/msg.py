#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import hashlib
import urlparse
import logging
import Cookie
from collections import Mapping
from IPy import IP

from complexconfig.configcontainer import configcontainer

from .bson.objectid import ObjectId
from .befilteredexception import BeFilteredException
from .path_normalizer import normalize_path
import settings


logger = settings.init_logging("sniffer.httpmsg")

sniffer_config = configcontainer.get_config("sniffer")

suffix_config = sniffer_config.item(key="filter.static.suffixes", caching=60,
                                    default={"gif", "png", "ico", "css", "js", "csv", "txt", "jpeg", "jpg", "woff",
                                             "ttf"},
                                    cb_load=lambda raw: set(raw.lower().split(",")) if raw else set())

filtered_hosts_config = sniffer_config.item(key="filter.traffic.domains", caching=60, default=set(),
                                            cb_load=lambda raw: set(raw.lower().split(",")) if raw else set())

filtered_urls_config = sniffer_config.item(key="filter.traffic.urls", caching=60, default=set(),
                                           cb_load=lambda raw: set(raw.lower().split(",")) if raw else set())

filtered_clients_config = sniffer_config.item(key="filter.traffic.client_ips", caching=60, default=set(),
                                              cb_load=lambda raw: {IP(_) for _ in (raw.split(",") if raw else set())})
filtered_servers_config = sniffer_config.item(key="filter.traffic.server_ips", caching=60, default=set(),
                                              cb_load=lambda raw: {IP(_) for _ in (raw.split(",") if raw else [])})

encrypt_keys_config = sniffer_config.item(key="filter.encryption.names", default={"passwd", "password"}, caching=60,
                                          cb_load=lambda raw: set(raw.lower().split(",")) if raw else set())
encrypt_salt_config = sniffer_config.item(key="filter.encryption.salt", caching=60, default="12345678")

# if we should use port in the uri
sniffer_host_port_preserve_config = sniffer_config.boolean_item("sniffer.host.port.preserve", caching=60, default=False)

# determine sid, uid, did
sniffer_sid_keyset_config = sniffer_config.item(key="sniffer.sid.keyset", caching=60, default=set(),
                                                cb_load=lambda raw: set(raw.split(",") if raw else set()))
COMMON_SESSIONIDS = {"session_id", "sessionid", "jsessionid", "phpsessid", "aspsessionid", "asp.net_sessionid",
                     "cgisessid"}
sniffer_uid_keyset_config = sniffer_config.item(key="sniffer.uid.keyset", caching=60, default=set(),
                                                cb_load=lambda raw: set(raw.split(",") if raw else set()))
sniffer_did_keyset_config = sniffer_config.item(key="sniffer.did.keyset", caching=60, default=set(),
                                                cb_load=lambda raw: set(raw.split(",") if raw else set()))
# ip index in the x-forward-for
sniffer_ip_index_config = sniffer_config.int_item(key="sniffer.ip_index", caching=60, default=-1)
sniffer_x_forward_names_config = sniffer_config.item(key="sniffer.x_forward.names", caching=60,
                                                     default=["X-FORWARDED-FOR", "HTTP-X-FORWARDED-FOR"],
                                                     cb_load=lambda raw: raw.split(",") if raw else list())


def get_flat_dict(raw_dict):
    """
    Get a dict with height of 1 from the raw dict, whose length may be bigger.

    This is useful when we want to extract the uid/did/sid from a specific field in the json payload.
    """
    result = {}
    if not raw_dict or not isinstance(raw_dict, Mapping):
        return result

    for k, v in raw_dict.items():
        if isinstance(v, (str, unicode, int)):
            result[k] = v
        elif isinstance(v, list):
            for _ in v:
                result.update(get_flat_dict(_))
        elif isinstance(v, Mapping):
            result.update(get_flat_dict(v))

    return result


def is_static(url):
    """
    Check if the url is for a static resource.
    """
    if not url:
        return True

    if "." not in url:
        return False

    suffix = url.rsplit(".", 1)[1].lower()
    if suffix in suffix_config.get():
        return True

    return False


def is_host_filtered(host):
    """
    Check if the msg with the given host is not needed.
    """
    if not host:
        return False

    for _ in filtered_hosts_config.get():
        if _ in host:
            return True

    return False


def is_url_filtered(url):
    """
    Check if the msg with the given uri is not needed.
    """
    if not url:
        return False

    for _ in filtered_urls_config.get():
        if _ in url:
            return True

    return False


def is_client_filtered(client):
    """
    Check if the msg with the given client ip is not needed.
    """
    if not client:
        return False

    for _ in filtered_clients_config.get():
        if client in _:
            return True

    return False


def is_server_filtered(server):
    """
    Check if the msg with the given server ip is not needed.
    """
    if not server:
        return False

    for _ in filtered_servers_config.get():
        if server in _:
            return True

    return False


def get_full_uri(host, port, path):
    if path and not path.startswith("/"):
        # path already have the host
        return path

    result = host
    if port != 80 and sniffer_host_port_preserve_config.get():
        result = result + ":" + str(port)
    result += path
    return result


##
def encrypt(raw):
    return hashlib.sha1(raw + encrypt_salt_config.get()).hexdigest()


def encrypt_json_dict(json_dict, encrypt_keys):
    if not json_dict:
        return {}

    for k, v in json_dict.items():
        if isinstance(v, list):
            json_dict[k] = encrypt_json_list(v, encrypt_keys)
        elif isinstance(v, Mapping):
            json_dict[k] = encrypt_json_dict(v, encrypt_keys)
        elif k.lower() in encrypt_keys and isinstance(v, (unicode, str)):
            json_dict[k] = encrypt(v)

    return json_dict


def encrypt_json_list(json_list, encrypt_keys):
    if not json_list:
        return []

    for i in range(len(json_list)):
        item = json_list[i]
        if isinstance(item, list):
            json_list[i] = encrypt_json_list(item, encrypt_keys)
        elif isinstance(item, Mapping):
            json_list[i] = encrypt_json_dict(item, encrypt_keys)
    return json_list


def encrypt_json_data(json_data):
    """
    encrypt the json data
    :param json_data: the raw data
    :return: encrypted data
    """

    if isinstance(json_data, Mapping):
        return encrypt_json_dict(json_data, encrypt_keys_config.get())
    elif isinstance(json_data, list):
        return encrypt_json_list(json_data, encrypt_keys_config.get())
    else:
        return json_data


def get_data_and_encrypted_json(json_text):
    """
    Get json data, and the encrypted version
    """

    if not json_text:
        return {}, ""

    try:
        json_data = json.loads(json_text)
        json_data = encrypt_json_data(json_data)
        return json_data, json.dumps(json_data)
    except:
        logger.warn("meet error while parsing json, %s", json_text)
        return {}, json_text


def get_params_and_encrypted_query(query):
    """
    Get query params, and the encrypted version
    :param query: the query may be from the url or request body
    :return: the params in dictionary or the encrypted_query
    """
    if not query:
        return {}, ""

    encrypt_keys = encrypt_keys_config.get()
    query_data = urlparse.parse_qs(query, keep_blank_values=1) or {}

    change_for_encryption = False
    if query_data:
        for param_key, param_values in query_data.items():
            if param_key.lower() not in encrypt_keys:
                continue

            param_values = map(encrypt, param_values)
            query_data[param_key] = param_values
            change_for_encryption = True

    if not change_for_encryption:
        return query_data, query

    param_tuples = []
    for param_key, param_values in query_data.items():
        for param_value in param_values:
            param_tuples.append((param_key, param_value))
    query = "&".join(["{}={}".format(k, v) for k, v in param_tuples])
    return query_data, query


def normalize_dict(in_dict):
    """
    normalize the dict in order to easy the usage.

    1. all the key is changed to lower case
    2. all the value will be prime type, the list will use the first value

    :param in_dict: raw dict
    :return: dict converted on 2 rules
    """
    if not in_dict:
        return {}

    result_dict = {}
    for k, v in in_dict.items():
        new_k = k.lower()
        new_v = ""
        if isinstance(v, (list, tuple)):
            if v:
                new_v = v[0]
        else:
            new_v = v
        result_dict[new_k] = new_v
    return result_dict


class Msg(object):

    def debug_processing(self):
        return False


class HttpMsg(Msg):

    def __init__(self, **kwargs):
        """
        Initializing the http msg with input data and do normalization.

        kwargs is dict, keys:
            source_ip:
            source_port:
            dest_ip:
            dest_port:
            method:
            host:
            uri:
            user_agent:
            status_msg:
            status_code:
            req_headers:
            resp_headers:
            ts_secs:
            ts_msecs:
            req_body_len:
            resp_body_len:
            req_content_type:
            resp_content_type:
            referer:
            debug_processing:
            req_body:
            resp_body:
            log_body:
        """

        logger.debug("start to build httpmsg")

        self._source_ip = kwargs.get("source_ip", "")
        self._source_port = int(kwargs.get("source_port", "0"))
        self._dest_ip = kwargs.get("dest_ip", "")
        self._dest_port = int(kwargs.get("dest_port", "0"))

        self._method = kwargs.get("method", "").upper()
        self._host = kwargs.get("host", "").lower()
        uri = kwargs.get("uri", "").lower()
        self._user_agent = kwargs.get("user_agent", "").lower()
        self._status_msg = kwargs.get("status_msg", "").lower()
        self._status_code = int(kwargs.get("status_code", "0"))
        self._req_headers = kwargs.get("req_headers", dict())
        self._resp_headers = kwargs.get("resp_headers", dict())

        ts_secs = int(kwargs.get('ts_secs', 0))
        ts_msecs = int(kwargs.get('ts_msecs', 0))
        request_time = ts_secs * 1000 + ts_msecs
        self._request_time = request_time

        # adjust source ip
        x_forward = ""
        x_forward_names = sniffer_x_forward_names_config.get()
        for x_forward_name in x_forward_names:
            x_forward = self._req_headers.get(x_forward_name, "")
            if x_forward:
                break
        if x_forward:
            ip = x_forward.split(",")[sniffer_ip_index_config.get()].strip()
            if ip:
                self._source_ip = ip
        self._xforward = x_forward

        # check if we need this msg
        if is_host_filtered(self._host):
            logger.debug("filter by host")
            raise BeFilteredException("host")

        if is_url_filtered(uri):
            logger.debug("filter by uri")
            raise BeFilteredException("uri")

        if is_client_filtered(self._source_ip):
            logger.debug("filter by client")
            raise BeFilteredException("source")

        if is_server_filtered(self._dest_ip):
            logger.debug("filter by server")
            raise BeFilteredException("dest")

        self._req_body_len = int(kwargs.get("req_body_len", "0"))
        self._resp_body_len = int(kwargs.get("resp_body_len", "0"))

        self._id = ObjectId()  # new id
        self._uid = ""
        self._did = ""
        self._sid = ""

        self._req_content_type = kwargs.get('req_content_type', '').lower()
        self._resp_content_type = kwargs.get('resp_content_type', '').lower()

        # get normalized referer, remove the scheme
        referer = kwargs.get("referer", "").lower()
        if "://" in referer:
            # remove "http/https"
            referer = referer.split("://", 1)[1]
        if not sniffer_host_port_preserve_config.get():
            parts = referer.split("/")
            if ":" in parts[0]:
                parts[0] = parts[0].split(":", 1)[0]
                referer = "/".join(parts)
        self._referer = referer

        # get full uri
        if uri.startswith("http"):
            uri = uri.split("://", 1)[-1]
        if "?" not in uri:
            uri_stem = get_full_uri(self._host, self._dest_port, uri)
            uri_query = ""
            uri_query_data = {}
            self._uri = uri_stem
        else:
            uri_stem, uri_query = uri.split("?", 1)
            uri_stem = get_full_uri(self.host, self.dest_port, uri_stem)
            uri_query_data, uri_query = get_params_and_encrypted_query(uri_query)
            self._uri = "{}?{}".format(uri_stem, uri_query)

        self._uri_stem = uri_stem
        self._uri_query = uri_query

        # consider uri with host again
        if is_url_filtered(self._uri_stem):
            logger.debug("filter by uri")
            raise BeFilteredException("uri")

        self._uri_query_data = uri_query_data
        self._uri_query_data = normalize_dict(self._uri_query_data)

        succ, page, new_dict = normalize_path(self._uri_stem, self._uri_query_data)
        if succ:
            self._page = page
            if new_dict:
                self._uri_query_data.update(new_dict)
                new_dict_str = "&".join(map(lambda item: "{}={}".format(item[0], item[1]), new_dict.items()))
                if self._uri_query:
                    self._uri_query = "{}&{}".format(self._uri_query, new_dict_str)
                else:
                    self._uri_query = new_dict_str
        else:
            # use raw uri stem as dict
            self._page = self._uri_stem

        self._is_static = is_static(self._uri_stem)

        self._debug_processing = kwargs.get("debug_processing", False)

        self._req_body = kwargs.get("req_body", "")
        self._resp_body = kwargs.get("resp_body", "")

        if "application/json" in self._req_content_type or \
                (not self._req_content_type and self._req_body.startswith("{")):
            self._req_json_data, self._req_body = get_data_and_encrypted_json(self._req_body)
        else:
            self._req_json_data = {}

        if "x-www-form-urlencoded" in self._req_content_type:
            self._req_form_data, self._req_body = get_params_and_encrypted_query(self._req_body)
        else:
            self._req_form_data = {}

        if "application/json" in self._resp_content_type or \
                (not self._resp_content_type and self._resp_body.startswith("{")):
            self._resp_json_data, self._resp_body = get_data_and_encrypted_json(self._resp_body)
        else:
            self._resp_json_data = {}

        if "x-www-form-urlencoded" in self._resp_content_type:
            self._resp_form_data, self._resp_body = get_params_and_encrypted_query(self._resp_body)
        else:
            self._resp_form_data = {}

        self._req_flat_json_data = get_flat_dict(self._req_json_data)
        self._resp_flat_json_data = get_flat_dict(self._resp_json_data)

        self._log_body = bool(kwargs.get("log_body", False))

        # XXX key not exists now
        self._r_type = "api"

        # cookie
        self._cookie_data = {}
        cookie = self._req_headers.get("COOKIE", "")
        # strange hack
        if cookie:
            cookie = cookie.replace("\\x", "x")
        if cookie:
            c = Cookie.SimpleCookie()
            c.load(str(cookie))
            self._cookie_data.update({k: v.value for k, v in c.items()})

        # headers: response headers with higher priority if there is name conflict
        self._headers_data = {}
        self._headers_data.update(self._req_headers)
        self._headers_data.update(self._resp_headers)

        set_cookie = self._resp_headers.get("SET-COOKIE", "")
        if set_cookie:
            set_cookie = set_cookie.replace("\\x", "x")
        if set_cookie:
            c = Cookie.SimpleCookie()
            c.load(set_cookie)
            self._cookie_data.update({k: v.value for k, v in c.items()})

        # normalize the dict
        self._cookie_data = normalize_dict(self._cookie_data)
        self._headers_data = normalize_dict(self._headers_data)
        self._req_flat_json_data = normalize_dict(self._req_flat_json_data)
        self._resp_flat_json_data = normalize_dict(self._resp_flat_json_data)
        self._req_form_data = normalize_dict(self._req_form_data)
        self._resp_form_data = normalize_dict(self._resp_form_data)

        # get the ids from payload
        self._uid = self.get_specific_id(sniffer_uid_keyset_config.get()) or ""
        self._did = self.get_specific_id(sniffer_did_keyset_config.get()) or ""
        self._sid = self.get_specific_id(sniffer_sid_keyset_config.get()) \
            or self.get_specific_id(COMMON_SESSIONIDS) or ""

        # 去掉这个测试逻辑
        # if not self._did:
        #    ip_ua = "%s@%s" % (self._source_ip or "", self._user_agent or "")
        #    ip_ua = hashlib.sha224(ip_ua).hexdigest()
        #    self._did = ip_ua

        if len(self._sid) > 15:
            self._sid = hashlib.sha224(self._sid).hexdigest()
        if self._uid:
            logger.info("get uid:%s", self._uid)
#        self._uid = "fake_{}".format(str(random.randint(0, 10)))

        logger.debug("successfully initialized a http msg")

    def get_specific_id(self, key_set):
        if not key_set:
            return ""

        result = ""
        for key in key_set:
            # headers -> cookie -> url -> form body -> json -> body
            result = self.headers_data.get(key) or self._cookie_data.get(key) or self._uri_query_data.get(key) \
                     or self.req_form_data.get(key) or self.resp_form_data or self._resp_flat_json_data.get(key) \
                     or self._req_flat_json_data.get(key)
            if not result:
                continue

            if isinstance(result, list):
                return str(result[0]) if result else ""
            else:
                return str(result)

    @property
    def source_ip(self):
        return self._source_ip

    @property
    def source_port(self):
        return self._source_port

    @property
    def dest_ip(self):
        return self._dest_ip

    @property
    def dest_port(self):
        return self._dest_port

    @property
    def method(self):
        """
        upper case
        """

        return self._method

    @property
    def host(self):
        """
        lower case
        """
        return self._host

    @property
    def user_agent(self):
        """
        lower case
        """
        return self._user_agent

    @property
    def status_msg(self):
        """
        lower case
        """
        return self._status_msg

    @property
    def status_code(self):
        return self._status_code

    @property
    def req_body_len(self):
        return self._req_body_len

    @property
    def resp_body_len(self):
        return self._resp_body_len

    @property
    def req_headers(self):
        return self._req_headers

    @property
    def resp_headers(self):
        return self._resp_headers

    @property
    def id(self):
        return self._id

    @property
    def uid(self):
        return self._uid

    @property
    def did(self):
        return self._did

    @property
    def sid(self):
        return self._sid

    @property
    def req_content_type(self):
        return self._req_content_type

    @property
    def resp_content_type(self):
        return self._resp_content_type

    @property
    def referer(self):
        return self._referer

    @property
    def xforward(self):
        return self._xforward

    @property
    def request_time(self):
        return self._request_time

    @property
    def uri(self):
        return self._uri

    @property
    def uri_stem(self):
        return self._uri_stem

    @uri_stem.setter
    def uri_stem(self, uri_stem):
        self._uri_stem = uri_stem

    @property
    def uri_query(self):
        return self._uri_query

    @uri_query.setter
    def uri_query(self, uri_query):
        self._uri_query = uri_query

    @property
    def uri_query_data(self):
        return self._uri_query_data

    @property
    def is_static(self):
        return self._is_static

    @property
    def req_body(self):
        return self._req_body

    @property
    def req_json_data(self):
        return self._req_json_data

    @property
    def req_form_data(self):
        return self._req_form_data

    @property
    def resp_body(self):
        return self._resp_body

    @property
    def resp_json_data(self):
        return self._resp_json_data

    @property
    def resp_form_data(self):
        return self._resp_form_data

    @property
    def log_body(self):
        return self._log_body

    @property
    def r_type(self):
        return self._r_type

    @property
    def debug_processing(self):
        return self._debug_processing

    @property
    def cookie_data(self):
        return self._cookie_data

    @property
    def headers_data(self):
        return self._headers_data

    @property
    def req_flat_json_data(self):
        return self._req_flat_json_data

    @property
    def resp_flat_json_data(self):
        return self._resp_flat_json_data

    @property
    def page(self):
        return self._page

    @page.setter
    def page(self, page):
        self._page = page

    def get_dict(self):
        return {
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "method": self.method,
            "host": self.host,
            "xforward": self.xforward,
            "user_agent": self.user_agent,
            "status_msg": self.status_msg,
            "status_code": self.status_code,
            "req_body_len": self.req_body_len,
            "resp_body_len": self.resp_body_len,
            "req_headers": self.req_headers,
            "resp_headers": self.resp_headers,
            "id": self.id,
            "uid": self.uid,
            "did": self.did,
            "req_content_type": self.req_content_type,
            "resp_content_type": self.resp_content_type,
            "referer": self.referer,
            "uri": self.uri,
            "req_body": self.req_body,
            "resp_body": self.resp_body,
            "log_body": self.log_body,
            "debug_processing": self.debug_processing,
            }

    def get_json(self):
        return json.dumps(self.get_dict())

    @staticmethod
    def from_dict(d):
        return HttpMsg(**d)

    @staticmethod
    def from_json(j):
        return HttpMsg.from_dict(json.loads(j))

    def __str__(self):
        return "HttpMsg[{}]".format(self.get_dict())


class TextMsg(Msg):

    def __init__(self, t, debug=False):
        self._t = t
        self._debug = debug

    @property
    def debug_processing(self):
        return self._debug

    @property
    def text(self):
        return self._t


