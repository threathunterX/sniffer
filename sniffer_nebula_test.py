import os
import yaml
import json
import time
from json import loads
from json import dumps
from requests import post
from requests import get
from requests import put
from requests import delete
from kafka import KafkaProducer
from kafka import KafkaConsumer
from kafka.errors import KafkaError
from threading import Thread
import redis


class Kafka_producer():
    '''
    使用kafka的生产模块
    '''

    def __init__(self, bootstrap_servers, kafkatopic):
        self.kafkatopic = kafkatopic
        self.producer = KafkaProducer(bootstrap_servers=bootstrap_servers)

    def send_json_data(self, params):
        try:
            parmas_message = json.dumps(params)
            producer = self.producer
            producer.send(self.kafkatopic, parmas_message.encode('utf-8'))
            producer.flush()
        except KafkaError as e:
            print(e)


class Kafka_consumer():
    '''
    使用Kafka—python的消费模块
    '''

    def __init__(self, bootstrap_servers, kafkatopic):
        self.kafkatopic = kafkatopic
        self.consumer = KafkaConsumer(self.kafkatopic, bootstrap_servers=bootstrap_servers)

    def consume_data(self):
        for message in self.consumer:
            # print json.loads(message.value)
            yield message


def log(*args):
    r = ''
    for a in args:
        r += str(a)
        r += ' ' * 10
    print(r)


class RequestsData(object):
    def __init__(self, url, data, cookies, method='get'):
        self.data = data
        self.url = url
        self.cookies = cookies
        self.method = method

    def request(self):
        m = dict(
            get=get,
            put=put,
            post=post,
            delete=delete,
        )
        method = m[self.method]
        text = "can't connection {}".format(self.url)
        code = 'None'
        header = {
            "connection": "close",
            "content-type": 'application/json',
        }
        try:
            if self.method in ['get', 'delete']:
                response = method(self.url, params=self.data, cookies=self.cookies, timeout=10,
                                  headers=header)
            elif self.method in ['post', 'put']:
                data = dumps(self.data, ensure_ascii=False).encode('utf8')
                response = method(self.url, data=data, timeout=8, headers=header, cookies=self.cookies)
            else:
                log('RequestsData error')
                raise ValueError
            text = response.text
            code = response.status_code
        except Exception as e:
            print("error", e)

        finally:
            return (text, code)


def open_config():
    f = open('docker-compose.yml', 'r', encoding='utf-8')
    cont = f.read()
    config = yaml.load(cont, Loader=yaml.FullLoader)
    log('config ->', config)
    return config


def host_port_from_config(config, host_str, port_str):
    e = config['services']['nebula_sniffer']['environment']
    host = None
    port = None
    for i in e:
        if host_str in i:
            # NEBULA_HOST=127.0.0.1
            start = i.find('=')
            host = i[start + 1:]
        if port_str in i:
            # NEBULA_HOST=127.0.0.1
            start = i.find('=')
            port = i[start + 1:]
    if host is None or port is None:
        log("nebula config error -> {}={} {}={}".format(host_str, host, port_str, port))
    return (host, port)


def ping_nebula_web(config):
    host, port = host_port_from_config(config, "NEBULA_HOST", "NEBULA_PORT")
    n = 'http://' + host + ':' + port
    r = RequestsData(n, {}, {})
    text, code = r.request()
    print('ping nebula url: {} status code {}'.format(n, code))


def ping_redis(config):
    try:
        host, port = host_port_from_config(config, "REDIS_HOST", "REDIS_PORT")
        r = redis.Redis(host=host, port=port, password='', decode_responses=True)
        r.set('nebula_test', 'threathunter')
        t = r.get('nebula_test')
        if t != "threathunter":
            log('redis is error')
        else:
            log('redis connection and test success')
    except:
        log("redis config is error, can't connection redis")
    return


def data_from_config(config, data_name):
    e = config['services']['nebula_sniffer']['environment']
    for i in e:
        if data_name in i:
            start = i.find('=')
            data = i[start + 1:]
            return data
    return None


def sources_mode(config):
    s = data_from_config(config, 'SOURCES')
    if s is None:
        log('SOURCES is error')
        return
    elif s == 'kafka':
        log('current sources mode is kafka')
    elif s == 'default':
        log('current sources mode is bro(default)')
    else:
        log('SOURCES error, please check it')
    return


def debug(config):
    _debug = data_from_config(config, 'DEBUG')
    if _debug == 'True':
        log("current open debug mode(debug=True)")
    elif _debug == 'False':
        log("current off debug mode(debug=False)")
    else:
        log('config is error')
    return


def ping_kafka_producer(config):
    b = data_from_config(config, 'BOOTSTRAP_SERVERS')
    t = data_from_config(config, 'TOPICS')
    producer = Kafka_producer(b, t)
    params = 'threathunter nebula test'
    for i in range(5):
        producer.send_json_data(params)
    log('kafka producer send message success: {} * 5'.format(params))
    return


def ping_kafka_consumer(config):
    b = data_from_config(config, 'BOOTSTRAP_SERVERS')
    t = data_from_config(config, 'TOPICS')
    consumer = Kafka_consumer(b, t)
    message = consumer.consume_data()
    r = []
    for msg in message:
        if len(r) >= 5:
            break
        else:
            r.append(msg)
    for v in r:
        value = v.value
        # log('kafka access message value', value)
        if b'threathunter nebula test' in value:
            log('kafka connection and test is ok')
            return
    log('kafka config and test is error')
    return


def thread_ping_kafka(config):
    log('start test connection kafka...')
    try:
        s = data_from_config(config, 'SOURCES')
        if s != 'kafka':
            return
        c = Thread(target=ping_kafka_consumer, args=(config,))
        p = Thread(target=ping_kafka_producer, args=(config,))

        c.start()
        time.sleep(3)
        p.start()
        c.join()
        p.join()
    except:
        log('kafka config error')
    return


def kafka_access_nginx(config):
    b = data_from_config(config, 'BOOTSTRAP_SERVERS')
    t = data_from_config(config, 'TOPICS')

    consumer = Kafka_consumer(b, t)
    message = consumer.consume_data()
    r = []
    for msg in message:
        if len(r) >= 5:
            break
        else:
            r.append(msg)
    for v in r:
        value = v.value
        # log('kafka access message', value)
        if b'host' in value and b'req_headers' in value:
            log('openresty -> nginx -> lua connection and test is ok')
            return
    log('openresty -> nginx -> lua connection and test is error')
    return r


def ping_openresty_nebula(web_url):
    r = RequestsData(web_url, {}, {})
    text, code = r.request()
    return


def ping_nginx_lua(web_url):
    for i in range(5):
        ping_openresty_nebula(web_url)
        time.sleep(0.5)
    return


def nginx_lua_to_kafka(config, web_url):
    log('start test nginx lua to kafka...')
    try:
        s = data_from_config(config, 'SOURCES')
        if s != 'kafka':
            return

        c = Thread(target=kafka_access_nginx, args=(config,))
        p = Thread(target=ping_nginx_lua, args=(web_url,))

        c.start()
        time.sleep(3)
        p.start()
        c.join()
        p.join()
    except:
        log('nginx lua to kafka error')

    return

def input_monitor_web():
    log('please input nginx lua software monitor web url or ip:port')
    log('eg: http://www.baidu.com/user')
    log('eg: 1.1.1.1:9999')
    a = input("please input:")
    return a

def main():
    web_url = input_monitor_web()
    c = open_config()
    debug(c)
    sources_mode(c)
    ping_nebula_web(c)
    ping_redis(c)
    thread_ping_kafka(c)
    nginx_lua_to_kafka(c, web_url)
    log('nebula and sniffer test complete')


def init():
    log('init python lib')
    # pip3 install PyYAML
    # pip3 install kafka
    # pip3 install redis

    # os.system('pip3 install kafka')
    # os.system('pip3 install redis')
    return


if __name__ == '__main__':
    # init()
    main()
