const FileType = require('file-type');
const setCookie = require('set-cookie-parser');
const isImage = require('is-image');
const fs = require('fs');
const path = require('path');
const isSvg = require('is-svg');
const request = require('postman-request');
const qs = require('querystring');
const JSON5 = require('json5');
const ATools = require('apipost-tools');
const Base64 = require('js-base64');
const CryptoJS = require("crypto-js");
const UrlParse = require('url-parse');
const Hawk = require('hawk');
const parsers = require('www-authenticate').parsers;
const _ = require('lodash');
const aws4 = require('aws4');
const EdgeGridAuth = require('akamai-edgegrid/src/auth');
const ntlm = require('httpntlm').ntlm;
const crypto = require('crypto');
const OAuth = require('oauth-1.0a');
// const pmEventUtil = require('pm-event-util');


// Apipost 发送模块
class ApipostRequest {
    requstloop: number;
    maxrequstloop: number;
    followRedirect: any;
    strictSSL: boolean;
    https: any;
    timeout: number;
    proxy: any;
    proxyAuth: any;
    version: string;
    jsonschema: any;
    target_id: any;
    // 构造函数
    constructor(opts?: any) {
        if (!opts) {
            opts = {};
        }

        this.requstloop = 0; // 初始化重定向

        // 配置项
        this.maxrequstloop = parseInt(opts.maxrequstloop) > 0 ? parseInt(opts.maxrequstloop) : 5; // 最大重定向次数
        this.followRedirect = opts.hasOwnProperty('followRedirect') ? opts.followRedirect : 1; // 是否允许重定向 1 允许 -1 不允许
        this.strictSSL = !!opts.strictSSL ?? 0;
        this.https = opts.https ?? { // 证书相关
            "rejectUnauthorized": -1, // 忽略错误证书 1 -1
            "certificateAuthority": '', // ca证书地址
            "certificate": '', // 客户端证书地址
            "key": '', //客户端证书私钥文件地址
            "pfx": '', // pfx 证书地址
            "passphrase": '' // 私钥密码
        };
        this.timeout = parseInt(opts.timeout) >= 0 ? parseInt(opts.timeout) : 0;
        this.proxy = opts.proxy ?? {};
        this.proxyAuth = opts.proxyAuth ?? 'username:password';
        this.target_id = opts.target_id;
        // 基本信息
        this.version = '7.0.3';
        this.jsonschema = JSON.parse(fs.readFileSync(path.join(__dirname, './apiSchema.json'), 'utf-8'));
    }

    // 结果转换函数
    ConvertResult(status: string, message: string, data?: any) {

        // if (status === 'error') {
        //     console.error(message);
        // }

        // (new pmEventUtil).send('SendResponseEventUtil', {
        //     status,
        //     message,
        //     data
        // }, function () {
        //     // console.log(err)
        // });

        return {
            status,
            message,
            data
        }
    }

    // 获取缓存目录
    getCachePath() {
        let cache_path = require('electron').remote.app.getPath('userData');

        if (process.env['LOCALAPPDATA']) {
            cache_path = process.env['LOCALAPPDATA'];
        }

        return cache_path;
    }

    // 格式化 query 参数
    formatQueries(arr: any[]) {
        let queries = '';

        if (arr instanceof Array) {
            arr.forEach(function (item) {
                if (parseInt(item.is_checked) === 1) {
                    queries += item.key + '=' + item.value + '&';
                }
            })
        }

        queries = queries.substr(-1) == '&' ? queries.substr(0, queries.length - 1) : queries;
        return qs.parse(queries);
    }

    // 用新的query对象(object)设置 uri 的query参数
    // return uri、host、path
    // setQueryString('https://echo.apipost.cn/get.php?id=1', {"id":[1,2], "token":3})
    // return {"uri":"https://echo.apipost.cn/get.php?id=1&id=2&token=3","host":"echo.apipost.cn","fullPath":"/get.php?id=1&id=2&token=3"}

    setQueryString(uri: string, paras: any) {
        let urls = new UrlParse(uri);
        let fullPath = urls.href.substr(urls.origin.length);
        let host = urls['host'];
        let baseUri = uri.substr(0, uri.indexOf(urls.query));

        if (urls.query !== '') {
            let queries = qs.parse(urls.query.substr(1));

            fullPath = urls['pathname'] + '?' + qs.stringify(Object.assign(queries, paras));
            uri = baseUri + '?' + qs.stringify(Object.assign(queries, paras));
        } else {
            fullPath += '?' + qs.stringify(paras);
            uri += '?' + qs.stringify(paras);
        }

        return { uri, host, fullPath, baseUri };
    }

    // 根据 auth 类型生成auth header参数
    createAuthHeaders(target: any) {
        let headers: any = {};
        let auth = target.request.auth;
        let { uri, host, fullPath, baseUri } = this.setQueryString(target.url, this.formatQueries(target.request.query.parameter));
        let entityBody = '';
        let rbody: any = this.formatRequestBodys(target);

        if (target.request.body.mode == 'urlencoded') {
            entityBody = rbody['form'];
        } else if (target.request.body.mode != 'form-data') {
            entityBody = rbody['body'];
        }

        switch (auth.type) {
            case 'noauth':
                break;
            case 'kv':
                headers[auth.kv.key] = auth.kv.value;
                break;
            case 'bearer':
                headers['Authorization'] = "Bearer " + auth.bearer.key;
                break;
            case 'basic':
                headers['Authorization'] = "Basic " + Base64.btoa(auth.basic.username + ':' + auth.basic.password);
                break;
            case 'digest':
                let ha1 = '';
                let ha2 = '';
                let response = '';
                let hashFunc = CryptoJS.MD5;

                if (auth.digest.algorithm == 'MD5' || auth.digest.algorithm == 'MD5-sess') {
                    hashFunc = CryptoJS.MD5;
                } else if (auth.digest.algorithm == 'SHA-256' || auth.digest.algorithm == 'SHA-256-sess') {
                    hashFunc = CryptoJS.SHA256;
                } else if (auth.digest.algorithm == 'SHA-512' || auth.digest.algorithm == 'SHA-512-sess') {
                    hashFunc = CryptoJS.SHA512;
                }

                let cnonce = auth.digest.cnonce == '' ? 'apipost' : auth.digest.cnonce;

                if (auth.digest.algorithm.substr(-5) == '-sess') {
                    ha1 = hashFunc(hashFunc(auth.digest.username + ':' + auth.digest.realm + ':' + auth.digest.password).toString() + ':' + auth.digest.nonce + ':' + cnonce).toString();
                } else {
                    ha1 = hashFunc(auth.digest.username + ':' + auth.digest.realm + ':' + auth.digest.password).toString();
                }

                if (auth.digest.qop != 'auth-int') {
                    ha2 = hashFunc(target.method + ':' + fullPath).toString();
                } else if (auth.digest.qop == 'auth-int') {
                    ha2 = hashFunc(target.method + ':' + fullPath + ':' + hashFunc(entityBody).toString()).toString();
                }

                if (auth.digest.qop == 'auth' || auth.digest.qop == 'auth-int') {
                    response = hashFunc(ha1 + ':' + auth.digest.nonce + ':' + (auth.digest.nc || '00000001') + ':' + cnonce + ':' + auth.digest.qop + ':' + ha2).toString();
                } else {
                    response = hashFunc(ha1 + ':' + auth.digest.nonce + ':' + ha2).toString();
                }

                headers['Authorization'] = "Digest username=\"" + auth.digest.username + "\", realm=\"" + auth.digest.realm + "\", nonce=\"" + auth.digest.nonce + "\", uri=\"" + fullPath + "\", algorithm=\"" + auth.digest.algorithm + "\", qop=" + auth.digest.qop + ",nc=" + (auth.digest.nc || '00000001') + ", cnonce=\"" + cnonce + "\", response=\"" + response + "\", opaque=\"" + auth.digest.opaque + "\"";
                break;
            case 'hawk':
                let options = {
                    ext: auth.hawk.extraData,
                    timestamp: auth.hawk.timestamp,
                    nonce: auth.hawk.nonce,
                    // payload: '{"some":"payload"}',                      // UTF-8 encoded string for body hash generation (ignored if hash provided)
                    // contentType: 'application/json',                    // Payload content-type (ignored if hash provided)
                    // hash: false,
                    app: auth.hawk.app,
                    dlg: auth.hawk.delegation
                }

                let { header } = Hawk.client.header(uri, target.method, {
                    credentials: {
                        id: auth.hawk.authId,
                        key: auth.hawk.authKey,
                        algorithm: auth.hawk.algorithm,
                    }, ...options
                });
                headers['Authorization'] = header;
                break;
            case 'awsv4':
                let awsauth = aws4.sign({
                    method: target.method,
                    host: host,
                    path: fullPath,
                    service: auth.awsv4.service,
                    region: auth.awsv4.region,
                    body: entityBody
                }, {
                    accessKeyId: auth.awsv4.accessKey,
                    secretAccessKey: auth.awsv4.secretKey,
                    sessionToken: auth.awsv4.sessionToken
                });

                Object.assign(headers, awsauth.headers);
                break;
            case 'edgegrid':
                let eg = EdgeGridAuth.generateAuth({
                    path: uri,
                    method: target.method,
                    headers: {},
                    body: entityBody
                }, auth.edgegrid.clientToken, auth.edgegrid.clientSecret, auth.edgegrid.accessToken, auth.edgegrid.baseUri, 0, auth.edgegrid.nonce, auth.edgegrid.timestamp);

                Object.assign(headers, eg.headers);
                break;
            case 'ntlm': // https://github.com/SamDecrock/node-http-ntlm
                Object.assign(headers, {
                    'Connection': 'keep-alive',
                    'Authorization': ntlm.createType1Message({
                        url: uri,
                        username: auth.ntlm.username,
                        password: auth.ntlm.password,
                        workstation: auth.ntlm.workstation,
                        domain: auth.ntlm.domain
                    })
                });
                break;

            case 'ntlm_close':
                Object.assign(headers, {
                    'Connection': 'close',
                    'Authorization': ntlm.createType3Message(auth.ntlm_close.type2msg, {
                        url: uri,
                        username: auth.ntlm.username,
                        password: auth.ntlm.password,
                        workstation: auth.ntlm.workstation,
                        domain: auth.ntlm.domain
                    })
                });
                break;
            case 'oauth1':
                let hmac = 'sha1';

                if (auth.oauth1.signatureMethod === 'HMAC-SHA1') {
                    hmac = 'sha1';
                } else if (auth.oauth1.signatureMethod === 'HMAC-SHA256') {
                    hmac = 'sha256';
                } else if (auth.oauth1.signatureMethod === 'HMAC-SHA512') {
                    hmac = 'sha512';
                } else {
                    // todo..
                    // 支持更多加密方式
                }
                const oauth = OAuth({
                    consumer: {
                        key: auth.oauth1.consumerKey,
                        secret: auth.oauth1.consumerSecret,
                        version: auth.oauth1.version ?? '1.0',
                        nonce: auth.oauth1.nonce,
                        realm: auth.oauth1.realm,
                        timestamp: auth.oauth1.timestamp,
                        includeBodyHash: auth.oauth1.includeBodyHash,
                    },
                    signature_method: auth.oauth1.signatureMethod,
                    hash_function(base_string: string, key: string) {
                        let hash = crypto.createHmac(hmac, key).update(base_string).digest('base64')
                        return hash;
                    },
                })

                const request_data = {
                    url: uri,
                    method: target.method,
                    data: auth.oauth1.includeBodyHash ? entityBody : {},
                    oauth_callback: auth.oauth1.callback
                }

                // console.log(request_data)
                const token = {
                    key: auth.oauth1.token,
                    secret: auth.oauth1.tokenSecret,
                }

                Object.assign(headers, oauth.toHeader(oauth.authorize(request_data, token)));
                break;
        }

        return headers;
    }

    // 格式化headers参数
    formatRequestHeaders(arr: any[], mode: string) {
        let headers: any = {};

        switch (mode) {
            case "json":
                headers['content-type'] = "application/json";
                break;
            case "xml":
                headers['content-type'] = "application/xml";
                break;
            case "javascript":
                headers['content-type'] = "application/javascript";
                break;
            case "plain":
                headers['content-type'] = "text/plain";
                break;
            case "html":
                headers['content-type'] = "text/html";
                break;
        }

        if (arr instanceof Array) {
            arr.forEach(function (item) {
                if (parseInt(item.is_checked) === 1) {
                    headers[item.key] = item.value
                }
            })
        }

        return headers;
    }

    // 格式化 urlencode 参数
    formatUrlencodeBodys(arr: any[]) {
        let bodys = '';

        if (arr instanceof Array) {
            arr.forEach(function (item) {
                if (parseInt(item.is_checked) === 1) {
                    bodys += item.key + '=' + item.value + '&';
                }
            })
        }

        bodys = bodys.substr(-1) == '&' ? bodys.substr(0, bodys.length - 1) : bodys;
        return bodys;
    }

    // 格式化 FormData 参数
    formatFormDataBodys(forms: any, arr: any[]) {
        if (arr instanceof Array) {
            arr.forEach(function (item) {
                if (parseInt(item.is_checked) === 1) {
                    let options: any = {};

                    if (typeof item.contentType === 'string') {
                        options['contentType'] = item.contentType;
                    }

                    if (item.type === 'File') {
                        forms.append(item.key, fs.createReadStream(item.value), options);
                    } else {
                        forms.append(item.key, item.value, options);
                    }
                }
            })
        }

        return forms;
    }

    // 格式化 json 参数
    formatRawJsonBodys(raw = '') {
        let bodys = '';

        if (ATools.isJson5(raw)) {
            bodys = JSON.stringify(JSON5.parse(raw));
        } else {
            bodys = raw;
        }

        return bodys;
    }

    // 格式化 其他 非json raw参数
    formatRawBodys(raw = '') {
        let bodys = raw;

        // if(ATools.isJson5(raw)){
        //     bodys = JSON.stringify(JSON5.parse(raw));
        // }else{
        //     bodys = raw;
        // }

        return bodys;
    }

    // 格式化 请求Body 参数
    formatRequestBodys(target: any) {
        let _body = {};

        switch (target.request.body.mode) {
            case "none":
                break;
            case "form-data":
                break;
            case "urlencoded":
                _body = {
                    form: this.formatUrlencodeBodys(target.request.body.parameter)
                }
                break;
            case "json":
                _body = {
                    body: this.formatRawJsonBodys(target.request.body.raw)
                }
                break;
            default:
                _body = {
                    body: this.formatRawBodys(target.request.body.raw)
                }
                break;
        }

        return _body;
    }

    // 格式化 请求Body 参数（用于脚本使用）
    formatDisplayRequestBodys(target: any) {
        let _body:any = {
            'request_bodys': {},
            'raw': {
                'mode': 'none'
            }
        };

        let arr = _.cloneDeep(target.request.body.parameter);

        switch (target.request.body.mode) {
            case "none":
                _body = {
                    'request_bodys': '',
                    'raw': {
                        'mode': 'none'
                    }
                }
                break;
            case "form-data":
                if (arr instanceof Array) {
                    let _raw : Array<any>= [];
                    arr.forEach(function (item) {
                        if (parseInt(item.is_checked) === 1) {
                            _body.request_bodys[item.key] = item.value;

                            if (item.type === 'File') {
                                _raw.push({
                                    key: item.key,
                                    type: 'file',
                                    src: item.value
                                });
                            } else {
                                _raw.push({
                                    key: item.key,
                                    type: "text",
                                    value: item.value
                                });
                            }
                        }
                    })

                    _body.raw = {
                        'mode': 'formdata',
                        'formdata': _raw
                    }
                }
                break;
            case "urlencoded":
                if (arr instanceof Array) {
                    let _raw : Array<any>= [];
                    arr.forEach(function (item) {
                        if (parseInt(item.is_checked) === 1) {
                            _body.request_bodys[item.key] = item.value;

                            _raw.push({
                                key: item.key,
                                value: item.value
                            });
                        }
                    })

                    _body.raw = {
                        'mode': 'urlencoded',
                        'urlencoded': _raw
                    }
                }
                break;
            default:
                _body = {
                    'request_bodys': this.formatRawJsonBodys(target.request.body.raw),
                    'raw': {
                        'mode': 'raw',
                        'raw': this.formatRawJsonBodys(target.request.body.raw),
                        'options': {
                            'raw': {
                                'language': target.request.body.mode
                            }
                        }
                    }
                }
                break;
        }

        return _body;
    }

    // 处理 响应参数
    async formatResponseData(error: any, response: any, body: any) {
        let res: any = {
            // client:{}, // 请求 client 属性
            // elapsedTime:0, // 请求总时间 （ms）
            responseTime: 0, // 请求总时间（elapsedTime 的别名） （ms）
            responseSize: 0, // 响应体大小（KB）
            // statusObj : {
            //     code:200,
            //     message:"OK"
            // }, // 响应状态
            status: "OK", // 兼容postman
            code: 200,  // 兼容postman
            timingPhases: {}, // 响应时间详情 （ms）
            resHeaders: {}, // 响应头
            headers: {}, // 响应头 兼容旧版
            header: [], // 响应头 ,数组格式 兼容postman
            fitForShow: "Monaco",// 是否适合展示的方式 [Monaco, Pdf, Image, Other（其他附件）]
            resMime: {},// 响应类型
            rawCookies: [], // 响应 cookie
            cookies: {}, // 响应 cookie 兼容旧版
            rawBody: "", // 响应体 fitForShow === Monaco 为响应内容，否则为响应文件存储路径
            stream: {   // 兼容postman
                "type": "Buffer",
                "data": []
            },
            raw: { //  兼容旧版
                status: 200,
                responseTime: 0,
                type: 'html',
                responseText: '',
            },
            json: {}
        };

        // 响应时间细节
        if (response.timingPhases) {
            res.timingPhases = response.timingPhases;
        }

        // 请求总时间
        if (response.elapsedTime >= 0) {
            res.responseTime = response.elapsedTime;
        }

        // 响应码
        // res.statusObj = {
        //     code:response.statusCode,
        //     message:response.statusMessage
        // }

        res.code = response.statusCode;
        res.status = response.statusMessage;
        res.raw.status = res.status; //响应状态码（200、301、404等）
        res.raw.responseTime = response.elapsedTime; //响应时间（毫秒）

        // 响应类型和 内容
        let resMime = await FileType.fromBuffer(body);

        if (!resMime) {
            res.fitForShow = "Monaco";
            res.rawBody = body.toString();

            if (isSvg(res.rawBody)) {
                res.fitForShow = "Image";
                res.rawBody = path.join(path.resolve(this.getCachePath()), 'response_' + this.target_id + '.svg');
                fs.writeFileSync(res.rawBody, body);

                // 拼装 raw
                res.raw.type = 'svg'
                res.raw.responseText = '';
            } else {
                if (ATools.isJson5(res.rawBody)) {
                    res.json = JSON5.parse(res.rawBody);
                }

                // 拼装 raw
                res.raw.type = ATools.isJson(res.rawBody) ? 'json' : ATools.isJsonp(res.rawBody) ? 'jsonp' : 'html'//响应类型（json等）
                res.raw.responseText = res.rawBody;
            }
        } else {
            res.resMime = resMime;

            if (res.resMime.ext === 'pdf') {
                res.fitForShow = "Pdf";
            } else if (isImage('test.' + res.resMime.ext)) {
                res.fitForShow = "Image";
            } else {
                res.fitForShow = "Other";
            }

            // 拼装 raw
            res.raw.type = res.resMime.ext
            res.raw.responseText = '';

            res.rawBody = path.join(path.resolve(this.getCachePath()), 'response_' + this.target_id + '.' + resMime.ext);
            fs.writeFileSync(res.rawBody, body);
        }

        let array = [];

        for (let i = 0; i < response.body.length; i++) {
            array[i] = response.body[i];
        }

        res.stream.data = array;

        // 响应头 和 cookie
        if (response.headers) {
            res.resHeaders = res.headers = response.headers;

            if (response.headers['set-cookie'] instanceof Array) {
                res.resCookies = setCookie.parse(response.headers['set-cookie']);

                for (let c in res.resCookies) {
                    res.cookies[res.resCookies[c].name] = res.resCookies[c].value;
                }
            }

            if (res.resHeaders.hasOwnProperty('content-length')) {
                res.responseSize = parseFloat((res.resHeaders['content-length'] / 1024).toFixed(2));
            } else {
                res.responseSize = parseFloat((body.toString().length / 1024).toFixed(2));
            }

            let header = [];
            for (let k in response.headers) {
                if (response.headers[k] instanceof Array) {
                    for (let h of response.headers[k]) {
                        header.push({
                            "key": k,
                            "value": h
                        })
                    }
                } else {
                    header.push({
                        "key": k,
                        "value": response.headers[k]
                    })
                }
            }

            res.header = header;
        }

        return res;
    }

    // 发送
    request(target: any, extra_headers = {}, extra_opts = {}) {
        return new Promise((reslove, reject) => {
            // // 配置项
            // this.https = opts.https ?? { // 证书相关
            //     "rejectUnauthorized": -1, // 忽略错误证书 1 -1
            //     "certificateAuthority":'', // ca证书地址
            //     "certificate": '', // 客户端证书地址
            //     "key":'', //客户端证书私钥文件地址
            //     "pfx":'', // pfx 证书地址
            //     "passphrase": '' // 私钥密码
            // };
            // this.proxy = opts.proxy ?? {};
            // this.proxyAuth = opts.proxyAuth ?? 'username:password';
            try {
                this.target_id = target.target_id;
                const that = this;
                const Validator = require('jsonschema').validate;
                that.requstloop++;

                if (!Validator(target, that.jsonschema).valid) {
                    reject(that.ConvertResult('error', '错误的JSON数据格式'));
                } else {

                    if (target.request.auth.type == 'ntlm') {
                        Object.assign(extra_opts, { forever: true });
                    }
                    // 获取发送参数
                    let options = {
                        // 拓展部分(固定) +complated
                        "encoding": null, // 响应结果统一为 Buffer
                        "verbose": !0, // 响应包含更多底层信息，如响应网络请求信息等
                        "time": !0, // 响应包含时间信息，此项 和 verbose 会有部分功能重叠
                        "followRedirect": !1,
                        // "followAllRedirects":!0,
                        // "maxRedirects":15,
                        "timeout": that.timeout, // 请求超时时间
                        "brotli": !0, // 请求 Brotli 压缩内容编码
                        "gzip": !0, // 请求 gzip 压缩内容编码
                        "useQuerystring": !0,
                        // "allowContentTypeOverride": !0,
                        "agent": false, // 代理

                        // 请求URL 相关 +complated
                        "uri": target.url, // 接口请求的完整路径或者相对路径（最终发送url = baseUrl + uri）
                        // "baseUrl": "https://go.apipost.cn/", // 前置url，可以用此项决定环境前置URL

                        // query 相关+complated
                        qs: that.formatQueries(target.request.query.parameter), // 此项会覆盖URL中的已有值

                        // "statusMessageEncoding":"utf8",

                        // 基本设置 +complated
                        "method": target.method, //请求方式，默认GET

                        // 请求Body（仅用于获取）
                        "_requestBody": this.formatDisplayRequestBodys(target),

                        // header头相关 +complated
                        "headers": {
                            "user-agent": `ApipostRequest/` + that.version + ` (https://www.apipost.cn)`,
                            ...this.formatRequestHeaders(target.request.header.parameter, target.request.body.mode),
                            ...this.createAuthHeaders(target),
                            ...extra_headers

                        }, // 请求头, kv 对象格式

                        // SSL 证书相关 +complated
                        'strictSSL': !!that.strictSSL, // 布尔值，是否强制要求SSL证书有效 1(true) 强制 !1(false) 非强制

                        // body 相关+complated
                        ...this.formatRequestBodys(target),

                        // 其他自定义
                        ...extra_opts

                    }

                    // 发送并返回响应
                    const r = request(options, async function (error: any, response: any, body: any) {
                        if (error) {
                            reject(that.ConvertResult('error', error.toString()));
                        } else {
                            let _headers = [];

                            if (_.isObject(response.request.headers)) {
                                for (let _key in response.request.headers) {
                                    _headers.push({
                                        key: _key,
                                        value: response.request.headers[_key]
                                    })
                                }
                            }

                            let _request: any = {
                                header: _headers
                            };

                            if (_.isObject(response.request)) {
                                _request = {
                                    url: response.request.href,
                                    uri: _.cloneDeep(JSON5.parse(JSON5.stringify(response.request.uri))),
                                    method: response.request.method,
                                    timeout: response.request.timeout,
                                    // qs:response.request.qs,
                                    contentType: response.request.headers['content-type'] ?? 'none',
                                    header: _headers,
                                    proxy: response.request.proxy,
                                    request_headers: response.request.headers,
                                    request_bodys: response.request['_requestBody'].request_bodys,
                                    body: response.request['_requestBody'].raw
                                };
                            }

                            reslove(that.ConvertResult('success', 'success', {
                                request: _request,
                                response: await that.formatResponseData(error, response, body)
                            }))

                            // 重定向的情况递归
                            if (that.followRedirect && that.requstloop < that.maxrequstloop) {
                                if (response.caseless.has('location') === 'location') { // 3xx  重定向
                                    let loopTarget = _.cloneDeep(target);
                                    loopTarget.url = loopTarget.request.url = response.caseless.get('location');
                                    that.request(loopTarget)
                                } else if (response.caseless.has('www-authenticate') === 'www-authenticate') { // http auth
                                    let loopTarget = _.cloneDeep(target);
                                    let parsed = new parsers.WWW_Authenticate(response.caseless.get('www-authenticate'));

                                    if (parsed.scheme == 'Digest') { // Digest
                                        Object.assign(loopTarget.request.auth.digest, parsed.parms);
                                        that.request(loopTarget)
                                    } else if (loopTarget.request.auth.type == 'ntlm') {
                                        loopTarget.request.auth.type == 'ntlm_close';
                                        Object.assign(loopTarget.request.auth.ntlm, {
                                            type2msg: ntlm.parseType2Message(response.caseless.get('www-authenticate')),

                                        });
                                        that.request(loopTarget);
                                    }
                                }
                            }
                        }
                    });

                    if (target.request.body.mode === 'form-data') {
                        that.formatFormDataBodys(r.form(), target.request.body.parameter);
                    }
                }
            } catch (e) {
                reject(this.ConvertResult('error', String(e)))
            }
        })
    }
}

export default ApipostRequest;
