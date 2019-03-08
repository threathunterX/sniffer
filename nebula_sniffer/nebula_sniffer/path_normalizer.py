#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
Page normalizer will modify uri_stem according the configuration.
"""
from complexconfig.configcontainer import configcontainer
import logging

logger = logging.getLogger("sniffer.pathnormalizer")
sniffer_config = configcontainer.get_config("sniffer")


class PathAdder(object):
    """
    Add some query values into page.

    The config should like "/testapi/index.html+user+password", when we meet the request on "/testapi/index.html", we
    will add query keys into path; for example, when we meet "/testapi/index.html?user=123&password=abc", we can get
    page "/testapi/index.html/user@123/password@abc", if the key has no value in query, we will use "____" instead
    """

    def __init__(self, config):
        self._query_key_list = list()
        self._prefix = ""
        parts = config.split("+")
        if not parts:
            return
        self._prefix = parts[0]
        self._query_key_list = parts[1:]

    def get_page(self, uri_stem, query_dict=None):
        """
        Add some values in the query_dict into the page, return the page.

        @:return [success, new_path]: the first param means if the path adder matches successfully, the second one
        returns the new path
        """
        if query_dict is None:
            query_dict = dict()

        if not self._query_key_list:
            return False, uri_stem

        if uri_stem != self._prefix:
            return False, uri_stem

        result_list = list()
        result_list.append(uri_stem)
        for key in self._query_key_list:
            value = query_dict.get(key, "____")
            result_list.append("{}@{}".format(key, value))

        result = "/".join(result_list)
        logger.debug("path adder change path %s to %s", uri_stem, result)
        return True, result


class PathRemover(object):
    """
    Remove some parts of path into query.

    The config should like "/testapi/index.html/user@****/password@****", when we meet the request on
    "/testapi/index.html/123/abc", we will get page "/testapi/index.html" and the query will have 2 more keys: user=123
    and password=abc
    """

    def __init__(self, config):
        self._path_parts = config.split("/")
        self._flags = [None] * len(self._path_parts)
        for idx, part in enumerate(self._path_parts):
            if part.endswith("@****"):
                key = part[:-5]
                if not key:
                    logger.error("invalid config for path remover: %s", config)
                    self._path_parts = []
                    raise RuntimeError("invalid config")

                self._flags[idx] = key

    def get_page(self, uri_stem):
        """
        Remove some parts of uri into query dict.

        @:return [success, new_path, new_query_objects]: the first param means if the path adder matches successfully,
        the second one returns the new path, the third one means the new query objects from path.
        """
        if not self._path_parts:
            return False, uri_stem, {}

        uri_stem_parts = uri_stem.split("/")
        if len(uri_stem_parts) != len(self._path_parts):
            # length not match
            return False, uri_stem, {}

        result_parts = []
        new_query_dict = {}
        match = False
        for idx in range(len(uri_stem_parts)):
            uri_stem_part = uri_stem_parts[idx]
            match_part = self._path_parts[idx]
            flag = self._flags[idx]

            if not flag:
                if uri_stem_part != match_part:
                    break
                else:
                    result_parts.append(uri_stem_part)
            else:
                result_parts.append(flag)
                new_query_dict[flag] = uri_stem_part
        else:
            match = True

        if not match:
            return False, uri_stem, {}
        else:
            result_page = "/".join(result_parts)
            logger.debug("path remover change path from %s to %s", uri_stem, result_page)
            return True, result_page, new_query_dict


def gen_path_adders(config_str):
    """
    generate path adders from the config.

    :param config_str:
    :return: the list of the adders
    """

    items = config_str.split(",")
    new_adders = list()
    for item in items:
        adder = PathAdder(item)
        new_adders.append(adder)

    return new_adders


def gen_path_removers(config_str):
    """
    generate path removers from the config
    :param config_str:
    :return: the list of the removers
    """

    items = config_str.split(",")
    new_removers = list()
    for item in items:
        try:
            remover = PathRemover(item)
            new_removers.append(remover)
        except:
            # ignore
            pass

    return new_removers


adders_config = sniffer_config.item(key="filter.log.added_suffixes", caching=60, default=list(),
                                    cb_load=gen_path_adders)
removers_config = sniffer_config.item(key="filter.log.ignored_suffixes", caching=60, default=list(),
                                      cb_load=gen_path_removers)


def normalize_path(uri_stem, query_dict):
    adders = adders_config.get()
    removers = removers_config.get()

    for adder in adders:
        succ, path = adder.get_page(uri_stem, query_dict)
        if succ:
            return True, path, {}

    for remover in removers:
        succ, path, new_dict = remover.get_page(uri_stem)
        if succ:
            return True, path, new_dict

    # not match
    return False, uri_stem, {}
