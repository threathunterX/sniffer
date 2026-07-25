#!/usr/bin/env python
# -*- coding: utf-8 -*-
import hashlib
import json

from threathunter_common.util import utf8


def extract_value_from_body(pattern, body):
    if not body:
        return ""

    m = pattern.search(body)
    if not m:
        return ""
    else:
        return m.group(2)


def get_md5(raw):
    if not raw:
        return ""

    md5 = hashlib.md5()
    md5.update(raw)
    return md5.hexdigest()


def escape_special_charactor(data):
    if not data:
        return data

    return data.replace("^M", "\r").replace("^J", "\n")


def get_python_json_friendly(data):
    if not data:
        return ""
    if "\\x" not in data:
        return data

    data = utf8(data)
    result = bytearray()
    length = len(data)
    cursor = 0
    while cursor < length:
        ch = data[cursor]
        if ch == "\\" and cursor <= length - 4 and data[cursor + 1].lower() == "x":
            hexvalue = data[cursor + 2:cursor + 4]
            try:
                result.append(int(hexvalue, 16))
                cursor += 4
                continue
            except Exception as err:
                pass

        result.append(ch)
        cursor += 1
    return str(result)


def get_json_obj(input_text):
    try:
        result = json.loads(input_text)
        return result
    except Exception as e1:
        input_text = get_python_json_friendly(input_text)
        result = json.loads(input_text)
        return result
    except Exception as e2:
        input_text = escape_special_charactor(input_text)
        result = json.loads(input_text)
        return result


if __name__ == "__main__":
    a = '{"@timestamp":"2017-09-07T20:59:43+08:00","@version":"1","remove_host":"http://www.example.com","clientip":"198.51.100.23","bytes":5,"cost":0.058,"referer":"-","agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36","time_local":"07/Sep/2017:20:59:43 +0800","xforward":"-","method":"POST","request":"/api/login.php?login_account=13800138000&game_key=demo&game_id=100&sid=10000&name=\\xB4\\xAB\\xC6\\xE6\\xB0\\xD4\\xD2\\xB5&sname=\\xBA\\xFE\\xC4\\xCF12\\xB7\\xFE&subaccount=1&from=1&way=1&refer=demo&uid=","uri":"/api/login.php","postData":"action=login&login_account=13800138000&password=<REDACTED>&ajax=0&gameid=100&sid=10000&ltype=3&s=1","cookieData":"session_id=<SESSION_ID>; account=demo_user; zone=cn","httpversion":"HTTP/1.1","status":302}'
    a = get_python_json_friendly(a)
    print a
