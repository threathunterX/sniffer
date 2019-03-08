#!/usr/bin/env python
# -*- coding: utf-8 -*-


from pylru import lrucache
from threathunter_common.redis.redisctx import RedisCtx
from complexconfig.configcontainer import configcontainer

sniffer_config = configcontainer.get_config("sniffer")
session_mapping_ttl = sniffer_config.int_item(key="sniffer.session_mapping.ttl", caching=60, default=86400 * 3)
local_cache = lrucache(10000)
NOT_EXIST_USER = "UsERNotExisT"


def store_user_session_mapping(user, session):
    if not user or not session:
        return

    # 1. set local lru cache
    local_cache[session] = user

    redis_key = "user_for_session_{}".format(session)
    # 2. set redis cache
    RedisCtx.get_instance().redis.setex(redis_key, user, session_mapping_ttl.get())


def get_user_from_session(session):
    if not session:
        return ""
    # 1. try load from local cache
    result = local_cache.get(session)

    if result == NOT_EXIST_USER:
        # should searched redis in the past and no value is found
        return ""
    elif result:
        # there is value
        return result
    else:
        # do redis ops
        pass

    # 2. try load from redis cache
    redis_key = "user_for_session_{}".format(session)
    result = RedisCtx.get_instance().redis.get(redis_key)
    # populate the cache
    if result:
        local_cache[session] = result
    else:
        local_cache[session] = NOT_EXIST_USER

    return result
