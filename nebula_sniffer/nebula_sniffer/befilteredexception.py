#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "nebula"


class BeFilteredException(Exception):

    def __init__(self, t):
        self._t = t

    @property
    def type(self):
        return self._t
