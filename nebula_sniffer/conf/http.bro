##! Implements base functionality for HTTP analysis.  The logging model is
##! to log request/response pairs and all relevant metadata together in
##! a single record.

@load base/utils/numbers
@load base/utils/files
@load base/frameworks/tunnels
@load base/frameworks/broker
@load base/frameworks/notice
@load base/frameworks/packet-filter

module HTTP;

export {
    redef enum Log::ID += { LOG };

    ## Indicate a type of attack or compromise in the record to be logged.
    type Tags: enum {
        ## Placeholder.
        EMPTY
    };

    ## This setting changes if passwords used in Basic-Auth are captured or
    ## not.
    const default_capture_password = F &redef;

    type Info: record {
        ## Timestamp for when the request happened.
        ts:                      time      &log;
        ## Unique ID for the connection.
        uid:                     string    &log;
        ## The connection's 4-tuple of endpoint addresses/ports.
        id:                      conn_id   &log;
        ## Represents the pipelined depth into the connection of this
        ## request/response transaction.
        trans_depth:             int     &log;
        ## Verb used in the HTTP request (GET, POST, HEAD, etc.).
        method:                  string    &log &optional;
        ## Value of the HOST header.
        host:                    string    &log &optional;
        ## URI used in the request.
        uri:                     string    &log &optional;
        ## Value of the "referer" header.  The comment is deliberately
        ## misspelled like the standard declares, but the name used here
        ## is "referrer" spelled correctly.
        referrer:                string    &log &optional;
        ## Value of the User-Agent header from the client.
        user_agent:              string    &log &optional;
        # the content type headers
        req_content_type:            string    &log &optional;
        res_content_type:            string    &log &optional;
        cookie:                  string    &log &optional;
        ## Actual uncompressed content size of the data transferred from
        ## the client.
        request_body_len:        int     &log &default=0;
        ## Actual uncompressed content size of the data transferred from
        ## the server.
        response_body_len:       int     &log &default=0;
        ## Status code returned by the server.
        status_code:             int     &log &optional;
        ## Status message returned by the server.
        status_msg:              string    &log &optional;
        ## Last seen 1xx informational reply code returned by the server.
        info_code:               int     &log &optional;
        ## Last seen 1xx informational reply message returned by the server.
        info_msg:                string    &log &optional;
        ## Filename given in the Content-Disposition header sent by the
        ## server.
        filename:                string    &log &optional;
        ## A set of indicators of various attributes discovered and
        ## related to a particular request/response pair.
        tags:                    set[Tags] &log;

        ## Username if basic-auth is performed for the request.
        username:                string    &log &optional;
        ## Password if basic-auth is performed for the request.
        password:                string    &log &optional;

        ## Determines if the password will be captured for this request.
        capture_password:        bool      &default=default_capture_password;

        ## All of the headers that may indicate if the request was proxied.
        proxied:                 set[string] &log &optional;

        ## response.
        range_request:           bool      &default=F;

        ## The following fields are customized ones for BigSec
        ##

        ## Recording http headers in the request.
        req_headers:                  string;
        ## Recording http headers in the response.
        resp_headers:                 string;
        ## Recording http body in the request(only for special urls).
        req_body:                     string;
        ## Recording http body in the response(only for special urls).
        resp_body:                    string;
        ## Whether to log the http body.
        log_body:                     bool;
        log_req_body:                 bool;
        log_resp_body:                bool;
        is_static:                    bool;
        is_filtered:                  bool;
    };


    ## record the necessary information exchanged with clients.
        type http_data: record {
        method:                string;
        host:                  string;
        uri:                   string;
        referrer:              string;
        user_agent:            string;
        req_content_type:      string;
        res_content_type:      string;
        cookie:                string;
        req_body_len:          int;
        resp_body_len:         int;
        status_code:           int;
        status_msg:            string;
        ts:                    double;
        orig_ip:               addr;
        orig_port:             port;
        resp_ip:               addr;
        resp_port:             port;
        req_headers:           string;
        resp_headers:          string;
        req_body:              string;
        resp_body:             string;
        log_body:              bool;
        is_static:             bool;
    };

    ## http body definition used in the body capture.
    type http_body: record
    {
        content_length: int;      # Value from the CONTENT-LENGTH header.
        size: int;                # Current size of accumulated body.
        data: string;               # Body data.
    };


    ## Structure to maintain state for an HTTP connection with multiple
    ## requests and responses.
    type State: record {
        ## Pending requests.
        pending:          table[int] of Info;
        ## Current request in the pending queue.
        current_request:  int                &default=0;
        ## Current response in the pending queue.
        current_response: int                &default=0;
	## Track the current deepest transaction.
	## This is meant to cope with missing requests
	## and responses.
	trans_depth:      int                &default=0;
    };

    ## A list of HTTP headers typically used to indicate proxied requests.
    const proxy_headers: set[string] = {
        "FORWARDED",
        "X-FORWARDED-FOR",
        "X-FORWARDED-FROM",
        "CLIENT-IP",
        "VIA",
        "XROXY-CONNECTION",
        "PROXY-CONNECTION",
    } &redef;

    ## A list of HTTP methods. Other methods will generate a weird. Note
    ## that the HTTP analyzer will only accept methods consisting solely
    ## of letters ``[A-Za-z]``.
    const http_methods: set[string] = {
        "GET", "POST", "HEAD", "OPTIONS",
        "PUT", "DELETE", "TRACE", "CONNECT",
        # HTTP methods for distributed authoring:
        "PROPFIND", "PROPPATCH", "MKCOL",
        "COPY", "MOVE", "LOCK", "UNLOCK",
        "POLL", "REPORT", "SUBSCRIBE", "BMOVE",
        "SEARCH"
    } &redef;

    ## Event that can be handled to access the HTTP record as it is sent on
    ## to the logging framework.
    global log_http: event(rec: Info);
}

# Add the http state tracking fields to the connection record.
redef record connection += {
    http:        Info  &optional;
    http_state:  State &optional;
};

global req_bodies: table[conn_id] of http_body;
global resp_bodies: table[conn_id] of http_body;
global log_url_patterns: vector of pattern = vector();
global log_url_substrings: vector of string = vector();
global static_resource_suffix: vector of string = vector();
global filtered_hosts: vector of string = vector();
global filtered_urls: vector of string = vector();
global filtered_clients: vector of addr = vector();
global filtered_clients_net: vector of subnet = vector();
global filtered_servers: vector of addr = vector();
global filtered_servers_net: vector of subnet = vector();
## send httpevent
global httpevent: event(data: http_data);

function new_http_body() : http_body
    {
    local body: http_body;

    body$size = 0;
    body$data = "";

    return body;
    }

# Initialize the HTTP logging stream and ports.
event bro_init() &priority=99
    {
    #Log::create_stream(HTTP::LOG, [$columns=Info, $ev=log_http, $path="http"]);
    Log::disable_stream(Weird::LOG); 
    Log::disable_stream(Broker::LOG); 
    Log::disable_stream(PacketFilter::LOG); 
    Analyzer::register_for_ports(Analyzer::ANALYZER_HTTP, ports);
	Broker::subscribe("/sniffer/cmds");
	Broker::listen();
	print fmt("bro server start on %s:%d",Broker::default_listen_address,Broker::default_port);
    }

function code_in_range(c: int, min: int, max: int) : bool
    {
    return c >= min && c <= max;
    }

function new_http_session(c: connection): Info
    {
    local tmp: Info;
    tmp$ts=network_time();
    tmp$uid=c$uid;
    tmp$id=c$id;
    # $current_request is set prior to the Info record creation so we
    # can use the value directly here.
    tmp$trans_depth = ++c$http_state$trans_depth;
    return tmp;
    }

function set_state(c: connection, is_orig: bool)
    {
	if ( ! c?$http_state )
		{
		local s: State;
		c$http_state = s;
		}

	# These deal with new requests and responses.
	if ( is_orig )
		{
		if ( c$http_state$current_request !in c$http_state$pending )
			c$http_state$pending[c$http_state$current_request] = new_http_session(c);

		c$http = c$http_state$pending[c$http_state$current_request];
		}
	else
		{
		if ( c$http_state$current_response !in c$http_state$pending )
			c$http_state$pending[c$http_state$current_response] = new_http_session(c);

		c$http = c$http_state$pending[c$http_state$current_response];
		}
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=5
    {
    if ( ! c?$http_state )
        {
        local s: State;
        c$http_state = s;
        }

    ++c$http_state$current_request;
    set_state(c, T);

    c$http$method = method;
    c$http$uri = to_lower(original_URI);
    c$http$is_filtered = F;

    # determin static resource
    c$http$is_static = F;
    local stem = split_string1(c$http$uri, /\?/)[0];
    local parts = split_string(stem, /\//);
    local page_name = parts[|parts|-1];
    if ("." in page_name) {
        parts = split_string(stem, /\./);
        local suffix = parts[|parts|-1];
        for (i in static_resource_suffix) {
            if (static_resource_suffix[i]== suffix) {
                c$http$is_static = T;
            }
        }
    }

    # determine log body
    c$http$log_req_body = F;
    c$http$log_resp_body = F;
    if ( !c$http$is_static ) {
        if (method == "POST") {
            c$http$log_req_body = T;
            c$http$log_resp_body = T;
        }
    }

    c$http$log_body = F;

    # determine filted hosts
    local client_ip = c$id$orig_h;
    local server_ip = c$id$resp_h;
    for (i in filtered_clients) {
        if (filtered_clients[i] == client_ip) {
            c$http$is_filtered = T;
        }
    }
    for (i in filtered_clients_net) {
        if (client_ip in filtered_clients_net[i]) {
            c$http$is_filtered = T;
        }
    }
    for (i in filtered_servers) {
        if (filtered_servers[i] == server_ip) {
            c$http$is_filtered = T;
        }
    }
    for (i in filtered_servers_net) {
        if (server_ip in filtered_servers_net[i]) {
            c$http$is_filtered = T;
        }
    }
    for (i in filtered_urls) {
        if (filtered_urls[i] in c$http$uri ) {
            c$http$is_filtered = T;
            break;
        }
    }
    if (c$http$is_filtered ) {
        c$http$log_req_body = F;
        c$http$log_resp_body = F;
    }

    if ( method !in http_methods )
        event conn_weird("unknown_HTTP_method", c, method);
    }

event http_reply(c: connection, version: string, code: count, reason: string) &priority=5
    {
    if ( ! c?$http_state )
        {
        local s: State;
        c$http_state = s;
        }

    # If the last response was an informational 1xx, we're still expecting
    # the real response to the request, so don't create a new Info record yet.
    if ( c$http_state$current_response !in c$http_state$pending ||
         (c$http_state$pending[c$http_state$current_response]?$status_code &&
           ! code_in_range(c$http_state$pending[c$http_state$current_response]$status_code, 100, 199)) )
        ++c$http_state$current_response;
    set_state(c, F);

    c$http$status_code = code;
    c$http$status_msg = reason;
    if ( code_in_range(code, 100, 199) )
        {
        c$http$info_code = code;
        c$http$info_msg = reason;
        }

    if ( c$http?$method && c$http$method == "CONNECT" && code == 200 )
        {
        # Copy this conn_id and set the orig_p to zero because in the case of CONNECT
        # proxies there will be potentially many source ports since a new proxy connection
        # is established for each proxied connection.  We treat this as a singular
        # "tunnel".
        local tid = copy(c$id);
        tid$orig_p = 0/tcp;
        Tunnel::register([$cid=tid, $tunnel_type=Tunnel::HTTP]);
        }
    }

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5
    {
    set_state(c, is_orig);
    local id = c$id;

    if ( is_orig ) { # client headers
        if ( ! c$http?$req_headers )
            c$http$req_headers = "";
            c$http$req_headers = fmt("%s$$$%s@@@%s", c$http$req_headers, name, value);

        if ( name == "REFERER" )
            c$http$referrer = value;

        else if ( name == "HOST" ){
            # The split is done to remove the occasional port value that shows up here.
            c$http$host = split_string1(value, /:/)[0];
            local url = value;
            if ( value[-1] != "/" && c$http$uri[0] != "/" )
                url = url + "/";
            url = url + c$http$uri;

            for (i in filtered_hosts) {
                if (filtered_hosts[i] in c$http$host) {
                    c$http$is_filtered = T;
                    break;
                }
            }

            # determin filtered
            if (c$http$is_filtered ) {
                c$http$log_req_body = F;
                c$http$log_resp_body = F;
            }
        }


        else if ( name == "RANGE" )
            c$http$range_request = T;

        else if ( name == "USER-AGENT" )
            c$http$user_agent = value;

        else if (name == "CONTENT-TYPE") { # XXX debug here
            c$http$req_content_type = value;
        }
        else if (name == "COOKIE") {
            c$http$cookie = value;
        }

        else if ( name in proxy_headers ) {
            if ( ! c$http?$proxied )
                c$http$proxied = set();
            add c$http$proxied[fmt("%s -> %s", name, value)];
        }

        else if ( name == "AUTHORIZATION" || name == "PROXY-AUTHORIZATION" ) {
            if ( /^[bB][aA][sS][iI][cC] / in value ) {
                local userpass = decode_base64_conn(c$id, sub(value, /[bB][aA][sS][iI][cC][[:blank:]]/, ""));
				#local userpass = decode_base64(sub(value, /[bB][aA][sS][iI][cC][[:blank:]]/, ""));
                local up = split_string(userpass, /:/);
                if ( |up| >= 2 ) {
                    c$http$username = up[0];
                    if ( c$http$capture_password )
                        c$http$password = up[1];
                }
                else {
                    c$http$username = fmt("<problem-decoding> (%s)", value);
                    if ( c$http$capture_password )
                        c$http$password = userpass;
                }
            }
        }
        if (id !in req_bodies) {
            req_bodies[id] = new_http_body();
        }

        if ( name == "CONTENT-LENGTH" ) {
            req_bodies[id]$content_length = to_int(value);
        }
    } else {
        if ( ! c$http?$resp_headers )
            c$http$resp_headers = "";
        c$http$resp_headers = fmt("%s$$$%s@@@%s", c$http$resp_headers, name, value);


        if (name == "CONTENT-TYPE") { # XXX debug here
            c$http$res_content_type = value;
            if (c$http?$is_filtered && !c$http$is_filtered && c$http$method == "GET" && c$http$res_content_type == "application/json") {
                c$http$log_resp_body = T;
            }
        }

        if (name == "SET-COOKIE") {
            if (!c$http?$cookie)
                c$http$cookie = "";
            c$http$cookie = cat(c$http$cookie, ";", value);
        }

        if (id !in resp_bodies) {
            resp_bodies[id] = new_http_body();
        }

        if ( name == "CONTENT-LENGTH" ) {
            
            resp_bodies[id]$content_length = to_int(value);

        }
    }
}

event http_end_entity(c:connection, is_orig: bool)
{
    local id = c$id;
    local body: http_body;
    if ( is_orig ) {
        if (id !in req_bodies)
            return;
        body = req_bodies[id];
        c$http$req_body = body$data;
        delete req_bodies[id];
    } else {
        if (id !in resp_bodies)
            return;
        body = resp_bodies[id];
        c$http$resp_body = body$data;
        delete resp_bodies[id];
    }
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    local id = c$id;
    local body: http_body;

    if (!c$http?$is_filtered)
        c$http$is_filtered = T;
    if (c$http$is_filtered) 
        return;
    if ( is_orig ) {
    if ( c$http?$log_req_body && c$http$log_req_body) {
    } else {
        return;
    }

    if (id !in req_bodies)
        return;

        body = req_bodies[id];

    body$data = cat(body$data, data);

    if (body?$content_length && (body$size + length < body$content_length))
    {
        # Accumulate partial HTTP body data and return.
        body$size += length;
        return;
    }
    }
    else {
    if ( c$http?$log_resp_body && c$http$log_resp_body) {
    } else {
        return;
    }
    if (id !in resp_bodies)
        return;

        body = resp_bodies[id];

    body$data = cat(body$data, data);

    if (body?$content_length && (body$size + length < body$content_length))
    {
        # Accumulate partial HTTP body data and return.
        body$size += length;
        return;
    }
    }
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority = 5
    {
    set_state(c, is_orig);

    if ( is_orig )
        c$http$request_body_len = stat$body_length;
    else
        c$http$response_body_len = stat$body_length;
    }

# receive config update
event update_logconfig(c: string)
    {
    print fmt("receive update_logconfig=%s", c);
    flush_all();
    local newVector: vector of string = vector();
    local substrings = split_string(c, /!!!/);
        for( s in substrings )
        {
        if ("" == substrings[s]) 
            break;
        newVector[|newVector|] = substrings[s];
        }
    log_url_substrings = newVector;
    }

event update_staticresourcesuffix(c: string)
    {
    print fmt("receive update_staticresourcesuffix=%s", c);
    flush_all();
    local newVector: vector of string = vector();
    local substrings = split_string(c, /,/);
        for( s in substrings )
        {
        if ("" == substrings[s]) 
            break;
        newVector[|newVector|] = to_lower(substrings[s]);
        }
    static_resource_suffix = newVector;
    }

event update_filteredhosts(c: string)
    {
    print fmt("receive update_filteredhosts=%s", c);
    flush_all();
    local newVector: vector of string = vector();
    local substrings = split_string(c, /,/);
        for( s in substrings )
        {
        if ("" == substrings[s]) 
            break;
        newVector[|newVector|] = to_lower(substrings[s]);
        }
    filtered_hosts = newVector;
    }
event update_filteredurls(c: string)
    {
    print fmt("receive update_filteredurls=%s", c);
    flush_all();
    local newVector: vector of string = vector();
    local substrings = split_string(c, /,/);
        for( s in substrings )
        {
        if ("" == substrings[s]) 
            break;
        newVector[|newVector|] = to_lower(substrings[s]);
        }
    filtered_urls = newVector;
    }

event update_filteredclients(c: string)
    {
    print fmt("receive update_filteredclients=%s", c);
    flush_all();
    local newAddresses: vector of addr = vector();
    local newSubnets: vector of subnet = vector();
    local substrings = split_string(c, /,/);
        for( s in substrings )
        {
        if ("" == substrings[s]) 
            break;
        if ("/" in substrings[s])
            newSubnets[|newSubnets|] = to_subnet(to_lower(substrings[s]));
        else
            newAddresses[|newAddresses|] = to_addr(to_lower(substrings[s]));
        }
    filtered_clients = newAddresses;
    filtered_clients_net = newSubnets;
    }

event update_filteredservers(c: string)
    {
    print fmt("receive update_filteredservers=%s", c);
    flush_all();
    local newAddresses: vector of addr = vector();
    local newSubnets: vector of subnet = vector();
    local substrings = split_string(c, /,/);
        for( s in substrings )
        {
        if ("" == substrings[s]) 
            break;
        if ("/" in substrings[s])
            newSubnets[|newSubnets|] = to_subnet(to_lower(substrings[s]));
        else
            newAddresses[|newAddresses|] = to_addr(to_lower(substrings[s]));
        }
    filtered_servers = newAddresses;
    filtered_servers_net = newSubnets;
    }

function sendHttpEvent(c: connection)
    {
            if (!c$http?$is_filtered)
                c$http$is_filtered = F;
            if (c$http$is_filtered) 
                return;

        #invalid request
            if ( ! c$http?$method )
                c$http$method = "";

            if ( ! c$http?$host )
                c$http$host = "";

            if ( ! c$http?$req_headers)
                c$http$req_headers = "";

            if ( ! c$http?$resp_headers)
                c$http$resp_headers = "";

            if ( ! c$http?$req_body )
                c$http$req_body = "";

            if ( ! c$http?$resp_body )
                c$http$resp_body = "";

            if ( ! c$http?$referrer )
                c$http$referrer = "";

            if ( ! c$http?$user_agent )
                c$http$user_agent = "";

            if( ! c$http?$req_content_type ) {
                c$http$req_content_type = "";
            }
            if( ! c$http?$res_content_type ) {
                c$http$res_content_type = "";
            }
            if (! c$http?$cookie) {
                c$http$cookie = "";
            }

            if ( ! c$http?$status_code )
                c$http$status_code = 0;

            if ( ! c$http?$status_msg )
                c$http$status_msg = "";

            if ( ! c$http?$uri )
                c$http$uri = "";

            if ( ! c$http?$log_body )
                c$http$log_body = F;

            if ( ! c$http?$is_static )
                c$http$is_static = F;

            local r: http_data;
            r$method = c$http$method;
            r$host = c$http$host;
            r$uri = c$http$uri;
            r$referrer = c$http$referrer;
            r$user_agent = c$http$user_agent;
            r$req_content_type = c$http$req_content_type;
            r$res_content_type = c$http$res_content_type;
            r$cookie = c$http$cookie;
            r$req_body_len = c$http$request_body_len;
            r$resp_body_len = c$http$response_body_len;
            r$status_code = c$http$status_code;
            r$status_msg = c$http$status_msg;
            r$ts = interval_to_double(network_time()-c$http$ts);
            r$orig_ip = c$http$id$orig_h;
            r$orig_port = c$http$id$orig_p;
            r$resp_ip = c$http$id$resp_h;
            r$resp_port = c$http$id$resp_p;
            r$req_headers = c$http$req_headers;
            r$resp_headers = c$http$resp_headers;
            r$req_body = c$http$req_body;
            r$resp_body = c$http$resp_body;
            r$log_body = c$http$log_body;
            r$is_static = c$http$is_static;
            event httpevent(r);
			local is_sent: bool = Broker::publish("/sniffer/events",Broker::make_event(httpevent,r));
			if ( ! is_sent )
				{
					print fmt("send httpevent failed.");
					return;
				}
#print fmt("send httpevent done.");
            return;
    }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority = -5
    {

    # The reply body is done so we're ready to log.
    if ( ! is_orig )
        {
        sendHttpEvent(c);
        # If the response was an informational 1xx, we're still expecting
        # the real response later, so we'll continue using the same record.
        if ( ! (c$http?$status_code && code_in_range(c$http$status_code, 100, 199)) )
            {
            Log::write(HTTP::LOG, c$http);
            delete c$http_state$pending[c$http_state$current_response];
            }
        }
    }

event connection_state_remove(c: connection) &priority=-5
    {
    # Flush all pending but incomplete request/response pairs.
    if ( c?$http_state )
        {
        for ( r in c$http_state$pending )
            {
            # We don't use pending elements at index 0.
            if ( r == 0 ) next;
            Log::write(HTTP::LOG, c$http_state$pending[r]);
            }
        }

    local id = c$id;
        if ( id in resp_bodies )
        {
        delete resp_bodies[id];
        }
        if ( id in req_bodies )
        {
        delete req_bodies[id];
        }


    }




