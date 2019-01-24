/**
 * Copyright JS Foundation and other contributors, http://js.foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

/**
    FUJITSU LIMITED 2018
    v1.0 2018/3/17 Tomohiro Nakajima : First release,Create parameters for IoT Platform
 **/

module.exports = function(RED) {
    "use strict";
    var request = require("request");
    var mustache = require("mustache");
    var querystring = require("querystring");
    var cookie = require("cookie");
    var hashSum = require("hash-sum");

    function HTTPRequest(n) {
        RED.nodes.createNode(this,n);
        var node = this;
        var baseurl = n.baseurl;
        var isTemplatedUrl = (baseurl||"").indexOf("{{") != -1;

        // Parameters of IoT Platform 
        var nodeMethod = n.method || "GET";
        var apiv = n.apiv;
        var tenantid = n.tenantid;
        var accesscode= n.accesscode;
        var resource= n.resource;
        var query= n.query;

        if(apiv === ""){
            apiv = "v1";
        }

        if (n.tls) {
            var tlsNode = RED.nodes.getNode(n.tls);
        }
        this.ret = n.ret || "txt";
        if (RED.settings.httpRequestTimeout) { this.reqTimeout = parseInt(RED.settings.httpRequestTimeout) || 120000; }
        else { this.reqTimeout = 120000; }

        var prox, noprox;
        if (process.env.http_proxy != null) { prox = process.env.http_proxy; }
        if (process.env.HTTP_PROXY != null) { prox = process.env.HTTP_PROXY; }
        if (process.env.no_proxy != null) { noprox = process.env.no_proxy.split(","); }
        if (process.env.NO_PROXY != null) { noprox = process.env.NO_PROXY.split(","); }

        this.on("input",function(msg) {
            var preRequestTimestamp = process.hrtime();
            var nodeUrl ="";
            
            // Using "msg.##" for Node  // 2018.03.17 START  
            if(msg.method){
                nodeMethod = msg.method;
            }
            if(msg.baseUrl){
                baseurl = msg.baseUrl;
            }
            if(msg.apiVersion){
                apiv = msg.apiVersion;
            }
            if(msg.tenantId){
                tenantid = msg.tenantId;
            }
            if(msg.accessCode){
                accesscode = msg.accessCode;
            }
            if(msg.resource){
                resource = msg.resource;
            }
            if(msg.query){
                query = msg.query;
            }
            // 2018.03.17 END

            node.status({fill:"blue",shape:"dot",text:"httpin.status.requesting"});
            
            // create nodeUrl form baseurl and apiv and tenantid and resource and query
            if(query === ""){
                nodeUrl = baseurl + "/" + apiv + "/" + tenantid + "/" + resource;
            } else {
                nodeUrl = baseurl + "/" + apiv + "/" + tenantid + "/" + resource + "/" +  query;
            }
            //node.warn(RED._("URL is >>" + nodeUrl));
            var url = nodeUrl; // || msg.url;
            
            
            if (isTemplatedUrl) {
                url = mustache.render(nodeUrl,msg);
            }
            if (!url) {
                node.error(RED._("httpin.errors.no-url"),msg);
                return;
            }
            // url must start http:// or https:// so assume http:// if not set
            if (url.indexOf("://") !== -1 && url.indexOf("http") !== 0) {
                node.warn(RED._("httpin.errors.invalid-transport"));
                node.status({fill:"red",shape:"ring",text:"httpin.errors.invalid-transport"});
                return;
            }
            if (!((url.indexOf("http://") === 0) || (url.indexOf("https://") === 0))) {
                if (tlsNode) {
                    url = "https://"+url;
                } else {
                    url = "http://"+url;
                }
            }

            var method = nodeMethod.toUpperCase() || "GET";
            
            
            //if (msg.method && n.method && (n.method !== "use")) {     // warn if override option not set
            //    node.warn(RED._("common.errors.nooverride"));
            //}
            //if (msg.method && n.method && (n.method === "use")) {
            //    method = msg.method.toUpperCase();          // use the msg parameter
            //}
            
            var opts = {};
            opts.url = url;
            opts.timeout = node.reqTimeout;
            opts.method = method;
            opts.headers = {};
            opts.encoding = null;  // Force NodeJs to return a Buffer (instead of a string)
            opts.maxRedirects = 21;
            var ctSet = "Content-Type"; // set default camel case
            var clSet = "Content-Length";
            if (msg.headers) {
                if (msg.headers.hasOwnProperty('x-node-red-request-node')) {
                    var headerHash = msg.headers['x-node-red-request-node'];
                    delete msg.headers['x-node-red-request-node'];
                    var hash = hashSum(msg.headers);
                    if (hash === headerHash) {
                        delete msg.headers;
                    }
                }
                if (msg.headers) {
                    for (var v in msg.headers) {
                        if (msg.headers.hasOwnProperty(v)) {
                            var name = v.toLowerCase();
                            if (name !== "content-type" && name !== "content-length") {
                                // only normalise the known headers used later in this
                                // function. Otherwise leave them alone.
                                name = v;
                            }
                            else if (name === 'content-type') { ctSet = v; }
                            else { clSet = v; }
                            opts.headers[name] = msg.headers[v];
                        }
                    }
                }
            }
            if (msg.hasOwnProperty('followRedirects')) {
                opts.followRedirect = msg.followRedirects;
            }
            if (msg.cookies) {
                var cookies = [];
                if (opts.headers.hasOwnProperty('cookie')) {
                    cookies.push(opts.headers.cookie);
                }

                for (var name in msg.cookies) {
                    if (msg.cookies.hasOwnProperty(name)) {
                        if (msg.cookies[name] === null || msg.cookies[name].value === null) {
                            // This case clears a cookie for HTTP In/Response nodes.
                            // Ignore for this node.
                        } else if (typeof msg.cookies[name] === 'object') {
                            cookies.push(cookie.serialize(name,msg.cookies[name].value));
                        } else {
                            cookies.push(cookie.serialize(name,msg.cookies[name]));
                        }
                    }
                }
                if (cookies.length > 0) {
                    opts.headers.cookie = cookies.join("; ");
                }
            }
            if (this.credentials && this.credentials.user) {
                opts.auth = {
                    user: this.credentials.user,
                    pass: this.credentials.password||""
                }
            }

            if (typeof msg.payload !== "undefined" && (method == "POST" || method == "PUT" || method == "PATCH" ) ) {
                if (typeof msg.payload === "string" || Buffer.isBuffer(msg.payload)) {
                    opts.body = msg.payload;
                } else if (typeof msg.payload == "number") {
                    opts.body = msg.payload + "";
                } else {
                    if (opts.headers['content-type'] == 'application/x-www-form-urlencoded') {
                        opts.body = querystring.stringify(msg.payload);
                    } else {
                        opts.body = JSON.stringify(msg.payload);
                        if (opts.headers['content-type'] == null) {
                            opts.headers[ctSet] = "application/json";
                        }
                    }
                }
                if (opts.headers['content-length'] == null) {
                    if (Buffer.isBuffer(opts.body)) {
                        opts.headers[clSet] = opts.body.length;
                    } else {
                        opts.headers[clSet] = Buffer.byteLength(opts.body);
                    }
                }
            }
            // revert to user supplied Capitalisation if needed.
            if (opts.headers.hasOwnProperty('content-type') && (ctSet !== 'content-type')) {
                opts.headers[ctSet] = opts.headers['content-type'];
                delete opts.headers['content-type'];
            }
            if (opts.headers.hasOwnProperty('content-length') && (clSet !== 'content-length')) {
                opts.headers[clSet] = opts.headers['content-length'];
                delete opts.headers['content-length'];
            }
            //put accesscode in Header area. 
            opts.headers['Authorization'] = "Bearer " + accesscode;	   
            var urltotest = url;
            var noproxy;
            if (noprox) {
                for (var i in noprox) {
                    if (url.indexOf(noprox[i]) !== -1) { noproxy=true; }
                }
            }
            if (prox && !noproxy) {
                var match = prox.match(/^(http:\/\/)?(.+)?:([0-9]+)?/i);
                if (match) {
                    opts.proxy = prox;
                } else {
                    node.warn("Bad proxy url: "+prox);
                    opts.proxy = null;
                }
            }
            if (tlsNode) {
                tlsNode.addTLSOptions(opts);
            }
            request(opts, function(err, res, body) {
                if(err) {
                    if(err.code === 'ETIMEDOUT' || err.code === 'ESOCKETTIMEDOUT') {
                        node.error(RED._("common.notification.errors.no-response"), msg);
                        node.status({fill:"red", shape:"ring", text:"common.notification.errors.no-response"});
                    }else{
                        node.error(err,msg);
                        node.status({fill:"red", shape:"ring", text:err.code});
                    }
                    msg.payload = err.toString() + " : " + url;
                    msg.statusCode = err.code;
                    node.send(msg);
                }else{
                    msg.statusCode = res.statusCode;
                    msg.headers = res.headers;
                    msg.responseUrl = res.request.uri.href;
                    msg.payload = body;
                    
                    if (msg.headers.hasOwnProperty('set-cookie')) {
                        msg.responseCookies = {};
                        msg.headers['set-cookie'].forEach(function(c) {
                            var parsedCookie = cookie.parse(c);
                            var eq_idx = c.indexOf('=');
                            var key = c.substr(0, eq_idx).trim();
                            parsedCookie.value = parsedCookie[key];
                            delete parsedCookie[key];
                            msg.responseCookies[key] = parsedCookie;
                        });
                    }
                    msg.headers['x-node-red-request-node'] = hashSum(msg.headers);
                    // msg.url = url;   // revert when warning above finally removed
                    if (node.metric()) {
                        // Calculate request time
                        var diff = process.hrtime(preRequestTimestamp);
                        var ms = diff[0] * 1e3 + diff[1] * 1e-6;
                        var metricRequestDurationMillis = ms.toFixed(3);
                        node.metric("duration.millis", msg, metricRequestDurationMillis);
                        if (res.client && res.client.bytesRead) {
                            node.metric("size.bytes", msg, res.client.bytesRead);
                        }
                    }
                    
                    // Convert the payload to the required return type
                    if (node.ret !== "bin") {
                        msg.payload = msg.payload.toString('utf8'); // txt
                        
                        if (node.ret === "obj") {
                            try { msg.payload = JSON.parse(msg.payload); } // obj
                            catch(e) { node.warn(RED._("httpin.errors.json-error")); }
                        }
                    }
                    node.status({});
                    node.send(msg);
                }
            });
            
        });

        this.on("close",function() {
            node.status({});
        });
    }

    RED.nodes.registerType("iotpf http",HTTPRequest,{
        credentials: {
            user: {type:"text"},
            password: {type: "password"}
        }
    });
}
