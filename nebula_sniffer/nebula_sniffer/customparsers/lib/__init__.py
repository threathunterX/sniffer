#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
#————————————————————————————————————————————————————
# FileName: __init__.py.py
# Version: 0.0.1
# Author : Rancho
# Email: 
# LastChange: 12/25/2018
# Desc:
# History:
#————————————————————————————————————————————————————
"""
# 例子
import json


def event(properties):
    properties = json.loads(properties)
    result = []

    r1 = dict()
    if 'login' in properties['url']:
        properties['result'] = 'T'
        r1['event_result'] = True
    else:
        r1['event_result'] = False
    if r1['event_result'] is True:
        r1['properties'] = properties
        result.append(r1)

    r2 = dict()
    if 'register' in properties['url']:
        properties['result'] = 'T'
        r2['event_result'] = True
    else:
        r2['event_result'] = False
    if r2['event_result'] is True:
        r2['properties'] = properties
        result.append(r2)

    return json.dumps(result)
