> # ⚠️ 本仓库已归档 —— Nebula 1.x 历史版本
>
> **本项目已停止维护,请勿用于生产环境。**
>
> Nebula 1.x 于 2019 年开源,此后代码未再更新。其依赖的技术栈(Python 2、
> OpenResty 1.11、Esper 6、jackson 1.9、commons-collections 3.2.1 等)均已
> 停止支持并存在已知漏洞,其中 commons-collections 3.2.1 含经典反序列化利用链。
>
> ### 👉 新版本:[Nebula 2.0](https://github.com/threathunterX/nebula2)
>
> 2.0 基于 Flink 重写,继承了 1.x 的全部风控领域资产(17 个事件模型、
> 253 个统计变量、170 条策略模板),并解决了 1.x 的架构与安全问题。
> 目前处于开发阶段,进展见新仓库。
>
> ### 关于本仓库的当前状态
>
> - 已清理历史遗留的凭据、内部地址与示例数据中的第三方信息;配置中的口令
>   已替换为 `CHANGE_ME_*` 占位符
> - 仓库保留公开,仅作历史存档与设计参考
> - **注意**:清理仅作用于当前代码,git 历史中仍保留原始内容;此前 fork
>   出去的副本亦不受影响
>
> ### 已移除的内容
>
> 本仓库原含 11 个以客户名命名的定制解析器,以及若干包含真实生产流量的
> 样例(其中一条含真实终端用户的手机号、口令与会话 Cookie)。这些内容
> 已全部移除或替换为合成数据。默认解析器 `defaultparser` 与全部驱动保留。

---

# sniffer —— 星云 Nebula 1.x 数据采集器

星云风控系统的数据采集端。负责从各种来源获取业务流量与日志,解析还原成标准化的
业务事件,推送给 Nebula 主系统做风控分析。星云"无需埋点即可接入"的能力由本组件实现。

## 工作原理

```
数据源 → Driver(采集驱动) → Parser(解析器) → HttpMsg 标准事件
      → gevent 队列 → Babel RPC(Redis 或 RabbitMQ)→ Nebula 主系统
```

主进程按数据源拆分为多个实例,每个实例绑定 CPU 核心,内部以 gevent 协程运行三个
循环:取消息、解析产出事件、经消息总线外发。内置指标采集、健康检查,以及 URL
归一化(把带参数的路径折叠为页面模式)。

## 支持的数据源

| 驱动 | 说明 |
|---|---|
| `brohttpdriver` | 内嵌 Bro/Zeek 2.6.1 解析旁路镜像流量,支持 BPF 过滤 —— 无埋点接入的主力方案 |
| `tsharkhttpsdriver` | 基于 tshark,可解密 HTTPS(需提供密钥) |
| `pktdriver` | 原始抓包 |
| `kafkadriver` | 消费 Kafka 中的业务日志 |
| `rabbitmqdriver` | 消费 RabbitMQ |
| `redislistdriver` | 消费 Redis List |
| `logstashdriver` / `logstashserver` | 对接 Logstash |
| `syslogdriver` / `syslogtextdriver` | 接收 syslog |
| `filedriver` | 尾随日志文件 |

另配套 `lua/kafka.lua`,一段 OpenResty 脚本,可在 Nginx 层直接把请求信息写入
Kafka,再由 `kafkadriver` 消费。这是接入成本最低的日志方案。

## 部署

```bash
docker compose up -d
```

全部参数通过环境变量注入,由 `entrypoint.sh` 写入配置文件。主要变量:

| 变量 | 说明 |
|---|---|
| `SOURCES` | 启用的驱动,如 `kafka`、`bro`、`syslog` |
| `NEBULA_HOST` / `NEBULA_PORT` | Nebula 主系统地址 |
| `REDIS_HOST` / `REDIS_PORT` | 消息总线(Babel)地址 |
| `DRIVER_INTERFACE` / `DRIVER_PORT` | 旁路抓包的网卡与端口 |
| `BOOTSTRAP_SERVERS` / `TOPICS` / `GROUP_ID` | Kafka 驱动参数 |

`bro/` 目录下提供 6 个镜像构建变体(CentOS / Alpine × 标准 / AF_PACKET / PF_RING),
用于不同流量规模下的抓包性能调优。

## 已知限制

- 代码基于 **Python 2**,已停止支持
- 内嵌的 Bro 2.6.1 为 2019 年前后版本(Bro 现已更名 Zeek 并多次大版本迭代)
- 依赖 `python_lib` 中的私有包(babel_python、threathunter_common 等),该仓库现为私有

## 2.0 中的对应组件

2.0 的采集器用 **Go** 重写为单二进制,保留本组件的多数据源设计,并新增一项本组件
不具备的能力:**敏感字段在采集端就地脱敏**,原文不进入下游。

tshark 的 HTTPS 解密驱动在 2.0 中不再提供 —— 密钥管理风险高,且在现代 TLS 配置
下基本不可行。

见 [nebula2/apps/collector](https://github.com/threathunterX/nebula2/tree/main/apps/collector)。
