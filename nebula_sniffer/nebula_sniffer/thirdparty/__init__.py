#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import hashlib
import base64

DEFAULT_COOKIE_ENCRYPT_KEYS = [
    "brdfdcdfegdfed",
    "huhdoikj45gd",
    "hytlpsdeddwd12d",
    "tytedd87dw4de",
    "huyhthtde89ds",
    "wdd,hyji87uyhk",
    "nbnddd8dwdwjh",
    "hgd89jddwdpo",
    "t6542iukmjhytds",
    "huyjyd98kmnb65d",
    "u9765tyhngrwd"
]
DEFAULT_COOKIE_ENCRYPT_KEYS = map(bytearray, DEFAULT_COOKIE_ENCRYPT_KEYS)


def md5(src_string):
    """
    md5 hash并返回base64加密结果.

    :param src_string:
    :return:
    """

    if not src_string:
        src_string = ""

    md5_string = hashlib.md5(src_string).hexdigest()
    return base64.b64encode(md5_string)


def encrypt(data, key):
    """
    根据数据和特殊的key进行解密, 返回byte[]

    :param data:
    :param key:
    :return:
    """
    if not data:
        return bytearray("")

    if isinstance(data, unicode):
        data = data.encode("UTF-8")

    # 开始二进制操作
    if isinstance(data, str):
        data = data.strip()
        data = bytearray(data)

    key_length = len(key)
    for i in range(len(data)):
        data[i] = data[i] ^ key[i % key_length]

    return str(data)


def encrypt_data(data):
    """
    加密数据

    :param data:
    :return:
    """

    if data:
        randint = random.Random().randint(0, 9)
        encrypted_data = encrypt(data, DEFAULT_COOKIE_ENCRYPT_KEYS[randint])
        result = "".join(["%02X" % ord(_) for _ in encrypted_data])
        result += str(randint)
    else:
        result = ""
    return result


def decrypt_data(data):
    if not data:
        return ""

    randint = int(data[-1])
    key = DEFAULT_COOKIE_ENCRYPT_KEYS[randint]
    decoded_data_length = (len(data) - 1) / 2
    result = bytearray([0] * decoded_data_length)
    for i in range(decoded_data_length):
        result[i] = chr(int(data[(2 * i):(2 * i + 2)], 16))

    # 重新解密一下
    result = encrypt(result, key)
    return str(result)


def encode_cookie(decoded_cookie):
    encoded_cookie = "" if decoded_cookie is None else decoded_cookie.strip()
    if encoded_cookie:
        encoded_cookie.replace("%", "%25")
        encoded_cookie.replace("=", "%3d")
        encoded_cookie.replace(",", "%2c")
        encoded_cookie.replace(";", "%3b")

    return encoded_cookie


def decode_cookie(encoded_cookie):
    if not encoded_cookie:
        return ""

    decoded_cookie = encoded_cookie.strip()
    if decoded_cookie:
        decoded_cookie.replace("%25", "%")
        decoded_cookie.replace("%3d", "=")
        decoded_cookie.replace("%2c", ",")
        decoded_cookie.replace("%3b", ";")

    return decoded_cookie


if __name__ == '__main__':
    data = encrypt_data("UD=345;BD=12007035")
    print 1111, data

    data = md5(data)
    print 2222, data

    data = encode_cookie(data)
    print 3333, data

    uid = "2179306559640A375477076456744D74576452380F6447345F6536793065596409375677046455744E745564573801644C343"
    print 4444, decrypt_data(decode_cookie(uid))
