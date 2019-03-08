#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
The module provide an lru cache to store limited number of items. It also provides ttl functionality so that
"""
from pylru import lrucache

from threathunter_common.util import millis_now

__author__ = 'lw'


class Cache(lrucache):
    """LRU cache that will store limited numbers of items, and too old ones will be discarded.
    """

    def __init__(self, size, ttl=60):
        """
        Get a lru cache
        :param size: the maximum items that will be stored
        :param ttl: the seconds that the item should be alive
        :return: a new cache
        """
        lrucache.__init__(self, size)
        self.ttl = ttl

    def __getitem__(self, key):
        current = millis_now()
        result = None
        v = lrucache.__getitem__(self, key)
        if v:
            ts = v["ts"]
            # check if the item has expired
            if (current - ts) / 1000 > self.ttl:
                result = None
            else:
                # update the ts, in order to make the item fresh
                v["ts"] = current
                result = v["value"]

        return result

    def __setitem__(self, key, value):
        current = millis_now()
        value = {"ts": current, "value": value}
        lrucache.__setitem__(self, key, value)
