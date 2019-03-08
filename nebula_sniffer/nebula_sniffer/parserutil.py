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
    a = '{"@timestamp":"2017-09-07T20:59:43+08:00","@version":"1","remove_host":"http://my.37.com","clientip":"106.5.193.200","bytes":5,"cost":0.058,"referer":"-","agent":"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729)","time_local":"07/Sep/2017:20:59:43 +0800","xforward":"-","method":"POST","request":"/api/login.php?login_account=13687380058&wd_GAME_KEY=mir&wd_GAME_ID=275&wd_SID=20252&wd_NAME=\xB4\xAB\xC6\xE6\xB0\xD4\xD2\xB5&wd_SNAME=\xBA\xFE\xC4\xCF12\xB7\xFE&wd_subaccount=1&tj_from=106&tj_way=1&refer=37wanty&uid=&showlogintype=4","uri":"/api/login.php","postData":"action=login&login_account=13687380058&password=d0lITE5HYkI2NjB3SUhMTjkyNHdJ&ajax=0&gameid=275&sid=20252&ltype=3&s=1","cookieData":"passport_37wan_com=705593519%7Ccj198952%7C1504785146000%7C904ad8297e6203b064ea0deb43bbdd8a; ispass_37wan_com=c6c0e6f0%7C1%7C4263bb73076ebf21b1b03b9b169f5fe4%7C1; 37wan_account=cj198952; 37loginrefer=LHd3dy4zNy5jb20sLCwsY2oxOTg5NTIsMCwyLDEwNiw%3D%7Cc4ccbe3601fb5d9160e6ba0731b83253; ting_passport_37_com=705593519%7Ccj198952%7C1504786234000%7C%7C74350%7C2784b5b34c703d369458f716dc3a24fb%7C1; zone=cn; tg_uv=S59KWLEmkmMBAAAAEQIk","httpversion":"HTTP/1.1","status":302}'
    a = get_python_json_friendly(a)
    print a
