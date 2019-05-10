local cjson = require "cjson"
local producer = require "resty.kafka.producer"

-- 定义kafka broker地址
local broker_list = {
    { host = "172.18.16.169", port = 9092 },
}

local topics = "nebula_nginx_lua"


function headers_format(headers)
    local strheaders = ''
    for key, value in pairs(headers) do
        strheaders = strheaders .. string.format("$$$%s@@@%s",string.upper(key),value)
    end
    return strheaders
end

function build_json_log()
    ngx.req.read_body()
    ngx.ctx.req_body = ngx.req.get_body_data()
end

function send_log_to_kafka()
    local log_json = {}

    log_json["host" ]= ngx.var.host
    log_json["uri"] = ngx.var.request_uri
    log_json["method"] = ngx.var.request_method

    log_json["cookie"] = ngx.var.http_cookie
    -- log_json["uri_args"] = ngx.req.get_uri_args()
    log_json["referer"] = ngx.var.http_referer
    log_json["user_agent"] = ngx.var.http_user_agent
    log_json["orig_ip"] = ngx.var.remote_addr
    log_json["orig_port"] = ngx.var.remote_port
    log_json["resp_ip"] = ngx.var.server_addr
    log_json["resp_port"] = ngx.var.server_port
    log_json["req_headers"] = headers_format(ngx.req.get_headers())

    log_json["req_content_type"] = ngx.var.content_type

    if ngx.ctx.req_body == nil or ngx.ctx.req_body == ''
    then
        log_json["req_body"] = ngx.var.request_body
    else
        log_json["req_body"] = ngx.ctx.req_body
    end

    if ngx.ctx.resp_body == nil or ngx.ctx.resp_body == ''
    then
        log_json["resp_body"] = ngx.var.resp_body
    else
        log_json["resp_body"] = ngx.ctx.resp_body
    end

    if (ngx.var.body_bytes_sent == '' or ngx.var.body_bytes_sent == nil)
    then
        log_json["resp_body_len"] = 0
    else
        log_json["resp_body_len"] = ngx.var.body_bytes_sent
    end

        if (ngx.var.content_length == '' or ngx.var.content_length == nil)
    then
        log_json["req_body_len"] = 0
    else
        log_json["req_body_len"] = ngx.var.content_length
    end

    log_json["resp_headers"] = headers_format(ngx.resp.get_headers())
    if (ngx.var.sent_http_content_type == '' or ngx.var.sent_http_content_type == nil)
    then
        log_json["resp_content_type"] = ngx.resp.get_headers()['content_type']
    else
        log_json["resp_content_type"] = ngx.var.sent_http_content_type
    end

    log_json["ts"] = ngx.var.request_time
    log_json["status_code"] = ngx.var.status
    log_json["status_msg"] = ngx.var.request_completion

    local message = cjson.encode(log_json)

    -- 定义kafka异步生产者
    local bp = producer:new(broker_list, { producer_type = "async" })
    -- 发送日志消息,send第二个参数key,用于kafka路由控制:
    -- key为nill(空)时，一段时间向同一partition写入数据
    -- 指定key，按照key的hash写入到对应的partition
    local ok, err = bp:send(topics, nil, message)
    if not ok then
        ngx.log(ngx.ERR, "send httplog to kafka err:", err)
        return
    else
        ngx.log(ngx.DEBUG, "send httplog to kafka success, topics: ",topics,", msg: ",message)
    end
    -- ngx.say(message)

end

send_log_to_kafka()
