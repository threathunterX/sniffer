#!/usr/bin/env python
# -*- coding: utf-8 -*-

import atexit
import time
import logging
import gevent
import threading
from threathunter_common.util import run_in_thread, run_in_subprocess
from produce import Produce
from settings import init_logging
from settings import Global_Conf_FN
from settings import Sniffer_Conf_FN
from settings import Logging_Datefmt
from settings import DEBUG

logger = init_logging('nebula.sniffer')


def print_debug_level():
    if DEBUG:
        print "logging debug level is 'DEBUG'"
        logger.info("logging debug level is 'DEBUG'")
    else:
        print "logging debug level is 'INFO'"
        logger.info("logging debug level is 'INFO'")


def get_parser(parser_name, parser_module):
    from nebula_sniffer import parser
    __import__("{}.{}".format("nebula_sniffer.customparsers", parser_module), globals=globals())
    return parser.Parser.get_parser(parser_name)


def get_driver(config, interface, parser, idx):
    """ global c """

    from complexconfig.configcontainer import configcontainer
    name = config['driver']
    if name == "bro":
        from nebula_sniffer.drivers.brohttpdriver import BroHttpDriver
        embedded = config.get("embedded", True)
        ports = config['ports']
        from nebula_sniffer.utils import expand_ports
        ports = expand_ports(ports)  # extend it
        start_port = int(config['start_port'])
        bpf_filter = config.get("bpf_filter", "")

        home = configcontainer.get_config("sniffer").get_string("sniffer.bro.home")

        if ports and home:
            driver = BroHttpDriver(interface=interface, embedded_bro=embedded, idx=idx, ports=ports, bro_home=home,
                                   start_port=start_port, bpf_filter=bpf_filter)
        elif ports:
            driver = BroHttpDriver(interface=interface, embedded_bro=embedded, idx=idx, ports=ports,
                                   start_port=start_port, bpf_filter=bpf_filter)
        elif home:
            driver = BroHttpDriver(interface=interface, embedded_bro=embedded, idx=idx, bro_home=home,
                                   start_port=start_port, bpf_filter=bpf_filter)
        else:
            driver = BroHttpDriver(interface=interface, embedded_bro=embedded, idx=idx,
                                   start_port=start_port, bpf_filter=bpf_filter)
        return driver

    if name == "tshark":
        from nebula_sniffer.drivers.tsharkhttpsdriver import TsharkHttpsDriver
        interface = interface
        ports = config["ports"]
        bpf_filter = config.get("bpf_filter", "")
        if ports:
            driver = TsharkHttpsDriver(interface=interface, ports=ports, bpf_filter=bpf_filter)
        else:
            driver = TsharkHttpsDriver(interface=interface, bpf_filter=bpf_filter)
        return driver

    if name == "syslog":
        from nebula_sniffer.drivers.syslogdriver import SyslogDriver
        port = int(config["port"])
        driver = SyslogDriver(port)
        return driver

    if name == "packetbeat":
        from nebula_sniffer.drivers.pktdriver import PacketbeatDriver
        port = int(config["port"])
        driver = PacketbeatDriver(port)
        return driver

    if name == "redislist":
        from nebula_sniffer.drivers.redislistdriver import RedisListDriver
        host = config["host"]
        port = int(config['port'])
        password = config.get('password', '')
        driver = RedisListDriver(host, port, password)
        return driver

    if name == "logstash":
        from nebula_sniffer.drivers.logstashdriver import LogstashDriver
        port = int(config['port'])
        driver = LogstashDriver(port)
        return driver

    if name == "rabbitmq":
        from nebula_sniffer.drivers.rabbitmqdriver import RabbitmqDriver
        amqp_url = config['amqp_url']
        queue_name = config['queue_name']
        exchange_name = config['exchange_name']
        exchange_type = config['exchange_type']
        durable = bool(config['durable'])
        routing_key = config['routing_key']
        driver = RabbitmqDriver(amqp_url, queue_name, exchange_name, exchange_type, durable, routing_key)
        return driver

    if name == "kafka":
        from nebula_sniffer.drivers.kafkadriver import KafkaDriver
        driver = KafkaDriver(config['topics'],
                             bootstrap_servers=config['bootstrap_servers'],
                             group_id=config['group_id'])
        return driver

    return None


def run_task(interface, idx, parser, driver, is_process=True):
    from nebula_sniffer.main import Main
    main = Main("client-{}-{}".format(interface, idx), parser, driver, idx, is_process)
    import sys
    import signal

    def interrupt_handler(signum, frame):
        logger.warn("handler signal:{}, exit now.".format(signum))
        main.stop()
        #driver.stop()
        sys.exit(0)

    if is_process:
        signal.signal(signal.SIGINT, interrupt_handler)
        signal.signal(signal.SIGTERM, interrupt_handler)
        logger.info("driver processes type: process")
    else:
        logger.info("driver processes type: thread")

    # init metrics
    init_metrics()
    main.start()
    while True:
        try:
            gevent.sleep(5)
        except BaseException as err:
            logger.error("meet error {}, exit sniffer and wait for rebooting".format(err))
            main.stop()
            break


def start():
    from complexconfig.configcontainer import configcontainer
    sniffer_config = configcontainer.get_config("sniffer")
    running_tasks = []
    running_drivers = []

    processes_type = sniffer_config.get_string("sniffer.processes.type")
    sources = sniffer_config.get_list('sniffer.sources')
    logger.info('sources: {}'.format(sources))

    for source in sources:
        source_config = sniffer_config.get_value("sniffer." + source)
        instances = source_config.get('instances', 1)
        parser_name = source_config['parser']['name']
        parser_module = source_config['parser']['module']
        interface = source_config["interface"]
        p = get_parser(parser_name, parser_module)

        for idx in range(1, instances+1):
            driver = get_driver(source_config, interface, p, idx)
            if processes_type == "process":
                # 获取到驱动并开启子进程进行数据处理
                task = run_in_subprocess(run_task, interface, idx, p, driver, True)
            else:
                task = run_in_thread(run_task, interface, idx, p, driver, False)
            running_tasks.append(task)
            running_drivers.append(driver)
            logger.warn("Finished starting source {} driver {} index {} on interface {}".format(source, driver, idx,
                                                                                                interface))

    def terminate():

        logger.warn("finish produce")
        Produce.stop()

        logger.warn("finish %d drivers", len(running_drivers))
        for d in running_drivers:
            try:
                d.stop()
            except:
                pass

        logger.warn("finish %d tasks", len(running_tasks))
        for t in running_tasks:
            if processes_type == "process":
                try:
                    t.terminate()
                except:
                    pass
            else:
                # daemon threads
                pass

    atexit.register(terminate)

    from threathunter_common.util import millis_now
    start_time = millis_now()
    while True:
        try:
            gevent.sleep(5)
            is_all_alive = True
            for t in running_tasks:
                if processes_type == "process":
                    if not t.is_alive():
                        is_all_alive = False
                        break
                else:
                    if not t.isAlive():
                        is_all_alive = False
                        break
            ttl = sniffer_config.get_int("sniffer.ttl", 5) * 1000
            if (millis_now() - start_time) > ttl:
                logger.warn("ttl has expire")
                break
            if not is_all_alive:
                logger.warn("some tasks has exited, exiting")
                break
        except Exception as err:
            logger.error("meet error {}, exit sniffer and wait for rebooting".format(err))
            break

    logger.warn("exiting sniffer")
    terminate()
    print "terminating"


def init_config():
    # import parts
    from complexconfig.loader.file_loader import FileLoader
    from complexconfig.loader.web_loader import WebLoader
    from complexconfig.parser.yaml_parser import YamlParser
    from complexconfig.parser.properties_parser import PropertiesParser
    from complexconfig.parser.threathunter_json_parser import ThreathunterJsonParser
    from complexconfig.config import Config, PeriodicalConfig, CascadingConfig
    from complexconfig.configcontainer import configcontainer

    # init the global config on /etc/nebula/nebula.conf
    global_config_loader = FileLoader("global_config_loader", Global_Conf_FN)
    global_config_parser = PropertiesParser("global_config_parser")
    # add sniffer prefix
    global_config = Config(global_config_loader, global_config_parser, cb_after_load=lambda x: {"sniffer": x})

    # init the sniffer module configuration on /etc/nebula/sniffer/sniffer.conf
    file_config_loader = FileLoader("file_config_loader", Sniffer_Conf_FN)
    file_config_parser = YamlParser("file_config_parser")
    # add sniffer prefix
    file_config = Config(file_config_loader, file_config_parser, cb_after_load=lambda x: {"sniffer": x})
    file_config.load_config(sync=True)

    print_with_time("successfully loaded the file config from {}".format(Sniffer_Conf_FN))

    web_config_loader = WebLoader("web_config_loader", file_config.get_string("sniffer.web_config.config_url"),
                                  params={"auth": file_config.get_string("sniffer.web_config.auth")})
    web_config_parser = ThreathunterJsonParser("web_config_parser")
    web_config = Config(web_config_loader, web_config_parser)
    web_config.load_config(sync=True)
    print "WebLoader: web_config_loader, sniffer.web_config.config_url:{}, params:{}".format(file_config.get_string("sniffer.web_config.config_url"),{"auth": file_config.get_string("sniffer.web_config.auth")})
    print_with_time("successfully loaded the web config from {}".format(
        file_config.get_string("sniffer.web_config.config_url")))

    # build the cascading config
    # file config will be updated every half an hour, while the web config will be updated every 5 minute
    cascading_config = CascadingConfig(PeriodicalConfig(global_config, 1800), PeriodicalConfig(file_config, 1800),
                                       PeriodicalConfig(web_config, 300))
    configcontainer.set_config("sniffer", cascading_config)

    print_with_time("successfully loaded config")


def init_sentry():
    """
    init sentry
    :return:
    """
    from raven import Client
    from raven.handlers.logging import SentryHandler
    from raven.conf import setup_logging

    from complexconfig.configcontainer import configcontainer
    config = configcontainer.get_config("sniffer")

    enable = config.get_boolean("sniffer.sentry.enable", False)
    if not enable:
        return

    sentry_level = config.get_string("sniffer.sentry.min_level", "error")
    sentry_server_name = config.get_string("sniffer.sentry.server_name", "")
    sentry_dsn = config.get_string("sniffer.sentry.dsn", "")
    if not sentry_dsn or not sentry_server_name:
        return

    print_with_time("sentry is enabled with dsn: {}, server_name: {}, level: {}".format(sentry_dsn,
                                                                                        sentry_server_name,
                                                                                        sentry_level))
    client = Client(sentry_dsn, name=sentry_server_name)
    handler = SentryHandler(client)
    if sentry_level.lower() == 'debug':
        handler.level = logging.DEBUG
    elif sentry_level.lower() == 'info':
        handler.level = logging.INFO
    else:
        handler.level = logging.ERROR
    setup_logging(handler)


def print_with_time(msg):
    """
    print msg with time, this is used beforer logger is initialized
    :return:
    """
    print "{}: {}".format(time.strftime(Logging_Datefmt), msg)
    logger.info("{}: {}".format(time.strftime(Logging_Datefmt), msg))

def init_autoparser():
    from nebula_parser.parser_initializer import init_parser, build_fn_load_event_schemas_on_web, \
        build_fn_load_parsers_on_web
    from complexconfig.configcontainer import configcontainer
    event_url = configcontainer.get_config("sniffer").get_string("sniffer.web_config.event_url")
    parser_url = configcontainer.get_config("sniffer").get_string("sniffer.web_config.parser_url")
    auth = configcontainer.get_config("sniffer").get_string("sniffer.web_config.auth")
    fn_load_event_schema = build_fn_load_event_schemas_on_web(event_url, auth)
    fn_load_parsers = build_fn_load_parsers_on_web(parser_url, auth)
    init_parser(fn_load_event_schema, fn_load_parsers)
    print_with_time("successfully init auto parsers, event from: {}, parser from: ".format(event_url, parser_url))


def init_redis():
    from complexconfig.configcontainer import configcontainer
    host = configcontainer.get_config("sniffer").get_string("sniffer.redis.host")
    port = configcontainer.get_config("sniffer").get_int("sniffer.redis.port")
    password = configcontainer.get_config("sniffer").get_string("sniffer.redis.password", "")

    from threathunter_common.redis.redisctx import RedisCtx
    RedisCtx.get_instance().host = host
    RedisCtx.get_instance().port = port
    RedisCtx.get_instance().password = password
    print_with_time("successfully init redis[host={},port={},password={}]".format(host, port, "*"*len(password)))


def init_metrics():
    from threathunter_common.metrics.metricsagent import MetricsAgent
    from complexconfig.configcontainer import configcontainer
    sniffer_config = configcontainer.get_config("sniffer")

    redis_host = sniffer_config.get_string('sniffer.redis_host')
    redis_port = sniffer_config.get_int('sniffer.redis_port')
    if not redis_host or not redis_port:
        print_with_time("invalid redis configuration")
        import sys
        sys.exit(-1)

    metrics_config = {
        'server': 'redis',
        'redis': {
            'type': 'redis',
            'host': redis_host,
            'port': redis_port
        }
    }
    MetricsAgent.get_instance().initialize_by_dict(metrics_config)
    print_with_time("successfully initializing metrics with config {}".format(str(metrics_config)))

if __name__ == "__main__":
    # logging level
    print_debug_level()

    # init logging
    print_with_time("starting sniffer")

    # init config
    print_with_time("start to init config")
    init_config()

    # init sentry
    print_with_time("start to init sentry")
    init_sentry()

    print_with_time("start to init Produce")
    Produce.start()

    # init redis
    print_with_time("start to init redis")
    init_redis()

    # init metrics
    print_with_time("start to init metrics")
    init_metrics()

    # init auto parser
    init_autoparser()

    # start the program
    print_with_time("start to processing")
    start()

