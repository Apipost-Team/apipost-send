const FileType = require('file-type'),
    setCookie = require('set-cookie-parser'),
    isImage = require('is-image'),
    fs = require('fs'),
    path = require('path'),
    isSvg = require('is-svg'),
    qs = require('querystring'),
    JSON5 = require('json5'),
    stripJsonComments = require("strip-json-comments"),
    ATools = require('apipost-tools'),
    Base64 = require('js-base64'),
    CryptoJS = require("crypto-js"),
    UrlParse = require('url-parse'),
    Hawk = require('hawk'),
    parsers = require('www-authenticate').parsers,
    _ = require('lodash'),
    aws4 = require('aws4'),
    EdgeGridAuth = require('akamai-edgegrid/src/auth'),
    ntlm = require('httpntlm').ntlm,
    crypto = require('crypto'),
    OAuth = require('oauth-1.0a'),
    MIMEType = require("whatwg-mimetype"),
    isBase64 = require('is-base64'),
    ASideTools = require('apipost-inside-tools'),
    { minimatch } = require('minimatch'),
    got = require('apipost-got'),
    tunnel = require('tunnel'),
    Validator = require('jsonschema').validate,
    pkginfo = require('pkginfo')(module),
    mime = require('mime'),
    { getObjFromRawHeaders } = require("rawheaders2obj"),
    FormData = require('form-data');
// Apipost 发送模块
class ApipostRequest {
    option: any;
    version: string;
    jsonschema: any;
    target_id: any;
    isCloud: number;
    requestLink: any;

    // 构造函数
    constructor(opts?: any) {
        if (!opts) {
            opts = {};
        }

        this.option = opts; // 初始化重定向

        // 配置项
        this.target_id = opts.target_id;
        this.isCloud = opts.hasOwnProperty('isCloud') ? (parseInt(opts.isCloud) > 0 ? 1 : -1) : -1; // update 0703
        this.requestLink = null;

        // 基本信息
        this.version = '0.0.100'; // update version for 7.0.13
        this.jsonschema = JSON.parse(fs.readFileSync(path.join(__dirname, './apipost-http-schema.json'), 'utf-8'));
    }

    // 结果转换函数
    ConvertResult(status: string, message: string, data?: any) {
        return ASideTools.ConvertResult(status, message, data)
    }

    // 获取缓存目录
    getCachePath() {
        return ASideTools.getCachePath();
    }

    // 格式化 query 参数
    formatQueries(arr: any[]) {
        let queries = '';

        if (arr instanceof Array) {
            arr.forEach(function (item) { // fixed bug
                if (parseInt(item.is_checked) === 1) {
                    item.value
                    if (item.value === '') {
                        queries += `${item.key}&`;
                    } else {
                        queries += `${item.key}=${item.value}&`;
                    }
                }
            })
        }

        return qs.parse(_.trimEnd(queries, '&'));
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
        } else if (!_.isEmpty(paras)) {
            fullPath += '?' + qs.stringify(paras);
            uri += '?' + qs.stringify(paras);
        }

        return { uri, host, fullPath, baseUri };
    }

    // 根据 auth 类型生成auth header参数
    createAuthHeaders(target: any) {
        let headers: any = {};
        let auth = target.request.auth;
        let { uri, host, fullPath, baseUri } = this.setQueryString(target.request.url, this.formatQueries(target.request.query.parameter));
        let entityBody = '';
        let rbody: any = this.formatRequestBodys(target);

        if (target.request.body.mode == 'urlencoded') {
            entityBody = rbody['form'];
        } else if (target.request.body.mode != 'form-data') {
            entityBody = rbody['body'];
        }

        try { // fixed 修复可能因第三方包报错导致的 bug
            switch (auth.type) {
                case 'noauth':
                    break;
                case 'kv':
                    if (_.trim(auth.kv.key) != '') {
                        headers[_.trim(auth.kv.key)] = auth.kv.value;
                    }
                    break;
                case 'bearer':
                    if (_.trim(auth.bearer.key) != '') {
                        headers['Authorization'] = "Bearer " + _.trim(auth.bearer.key);
                    }
                    break;
                case 'basic':
                    headers['Authorization'] = "Basic " + Base64.encode(auth.basic.username + ':' + auth.basic.password);
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

                    headers['Authorization'] = "Digest username=\"" + auth.digest.username + "\", realm=\"" + auth.digest.realm + "\", nonce=\"" + auth.digest.nonce + "\", uri=\"" + fullPath + "\", algorithm=\"" + auth.digest.algorithm + "\", qop=\"" + auth.digest.qop + "\",nc=" + (auth.digest.nc || '00000001') + ", cnonce=\"" + cnonce + "\", response=\"" + response + "\", opaque=\"" + auth.digest.opaque + "\"";
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

                    if (auth.hawk.algorithm === '') {
                        auth.hawk.algorithm = 'sha256';
                    }

                    if (auth.hawk.authId !== '' && auth.hawk.authKey !== '') { // fix bug
                        let { header } = Hawk.client.header(uri, target.method, {
                            credentials: {
                                id: auth.hawk.authId,
                                key: auth.hawk.authKey,
                                algorithm: auth.hawk.algorithm,
                            }, ...options
                        });
                        headers['Authorization'] = header;
                    }
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

                    const token = {
                        key: auth.oauth1.token,
                        secret: auth.oauth1.tokenSecret,
                    }

                    Object.assign(headers, oauth.toHeader(oauth.authorize(request_data, token)));
                    break;
            }
        } catch (e) { }


        return headers;
    }

    // 格式化headers参数
    formatRequestHeaders(arr: any[], mode: string) {
        let headers: any = {
            "User-Agent": `PostmanRuntime-ApipostRuntime/1.1.0`,
            "Cache-Control": "no-cache"
        };

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
                if (parseInt(item.is_checked) === 1 && _.trim(item.key) != '') {
                    let headerKey = item.key;

                    _.mapKeys(headers, function (v: any, k: any) {
                        if (_.toLower(k) == _.toLower(headerKey)) {
                            delete headers[k]
                        }
                    });

                    headers[_.trim(headerKey)] = item.value
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
                    if (item.key !== '') {
                        bodys += encodeURIComponent(item.key) + '=' + encodeURIComponent(item.value) + '&';
                        // bodys += item.key + '=' + item.value + '&';
                    }
                }
            })
        }

        bodys = bodys.substr(-1) == '&' ? bodys.substr(0, bodys.length - 1) : bodys;
        return bodys;
    }

    getBase64Mime(dataurl: string) {//将base64转换为文件
        try {
            let arr: any = dataurl.split(','), mime = arr[0].match(/:(.*?);/)[1];

            if (mime) {
                let mimeType = new MIMEType(mime);
                return { ext: mimeType['_subtype'], mime: mimeType.essence };
            } else {
                return null;
            }
        } catch (error) {
            return null;
        }
    }

    // 格式化 FormData 参数
    formatFormDataBodys(forms: any, arr: any[]) {
        let that = this;

        if (arr instanceof Array) {
            arr.forEach(function (item) {
                if (parseInt(item.is_checked) === 1) {
                    let options: any = {};

                    if (typeof item.contentType === 'string') {
                        options['contentType'] = item.contentType;
                    }

                    if (item.type === 'File') {
                        if (_.isArray(item?.value) && item.value.length > 0) {
                            item.value.forEach((path: any) => {
                                try {
                                    if (item.key !== '') {
                                        forms.append(item.key, fs.createReadStream(path), options);
                                    }
                                } catch (error) {

                                }
                            })
                        } else if (_.isArray(item?.fileBase64) && item.fileBase64.length > 0) {
                            let _file_names = typeof item.filename == 'string' ? item.filename.split('|') : [];
                            let _i = 0;
                            item.fileBase64.forEach((base64: any) => {
                                let fileBase64 = (isBase64(base64, { allowEmpty: false, allowMime: true }) || base64.indexOf('base64,') > 0) ? base64 : (isBase64(item.value, { allowEmpty: false, allowMime: true }) ? item.value : '')

                                if (isBase64(fileBase64, { allowEmpty: false, allowMime: true }) || base64.indexOf('base64,') > 0) { // 云端
                                    let _mime: any = that.getBase64Mime(fileBase64);
                                    let _temp_file: any = path.join(path.resolve(that.getCachePath()), `cache_${CryptoJS.MD5(fileBase64).toString()}`);

                                    try {
                                        fs.accessSync(_temp_file);
                                    } catch (err) {
                                        try {
                                            fs.mkdirSync(_temp_file, { recursive: true })
                                        } catch (e) { }
                                    }

                                    if (typeof _file_names[_i] == 'string') {
                                        _temp_file = path.join(_temp_file, `${_file_names[_i]}`);
                                    } else {
                                        _temp_file = path.join(_temp_file, `${CryptoJS.MD5(item.key).toString()}.${_mime ? _mime.ext : 'unknown'}`);
                                    }

                                    fs.writeFileSync(_temp_file, Buffer.from(fileBase64.replace(/^data:(.+?);base64,/, ''), 'base64'));

                                    if (item.key !== '') {
                                        forms.append(item.key, fs.createReadStream(_temp_file), options);
                                    }
                                    // fs.unlink(_temp_file, () => { }); // fix 文件上传bug
                                }

                                _i++;
                            })
                        }
                    } else {
                        if (item.key !== '') {
                            forms.append(item.key, item.value, options);
                        }
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
            try {
                bodys = stripJsonComments(raw);
                //                 bodys = JSONbig.stringify(JSONbig.parse(stripJsonComments(raw)));
            } catch (e) {
                bodys = JSON.stringify(JSON5.parse(raw));
            }
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
        let _body: any = {}, that: any = this;

        switch (_.get(target, 'request.body.mode')) {
            case "none":
                break;
            case "form-data":
                try {
                    const form: any = new FormData();
                    this.formatFormDataBodys(form, target.request.body.parameter);

                    _body = {
                        body: form,
                        header: form.getHeaders()
                    }
                } catch (e) {
                    _body = {
                        error: String(e)
                    }
                }
                break;
            case "urlencoded":
                _body = {
                    body: this.formatUrlencodeBodys(target.request.body.parameter),
                    header: {
                        "content-type": `application/x-www-form-urlencoded`
                    }
                };
                break;
            case "binary":
                const binary: any = _.get(target, 'request.body.binary');

                if (_.isObject(binary)) {
                    const filePath: any = String(_.get(binary, 'file_path'));
                    const base64Data: any = String(_.get(binary, 'data_url'));

                    try {
                        if (base64Data != '' && base64Data.indexOf('base64,') > 0) {
                            if (isBase64(base64Data, { allowEmpty: false, allowMime: true })) {

                                _body = {
                                    body: Buffer.from(base64Data.replace(/^data:(.+?);base64,/, ''), 'base64'),
                                    header: {
                                        "content-type": _.get(that.getBase64Mime(base64Data), 'mime') || 'application/octet-stream'
                                    }
                                };
                            }
                        } else if (_.isString(filePath) && filePath != '') {
                            const binaryBuffer = fs.createReadStream(filePath);

                            if (_.isBuffer(binaryBuffer)) {
                                _body = {
                                    body: binaryBuffer,
                                    header: {
                                        "content-type": mime.getType(filePath) || 'application/octet-stream'
                                    }
                                };
                            }
                        }
                    } catch (e) {
                        _body = {
                            error: String(e)
                        }
                    }
                }

                break;
            case "json":
                _body = {
                    body: this.formatRawJsonBodys(target.request.body.raw)
                };
                break;
            default:
                _body = {
                    body: this.formatRawBodys(target.request.body.raw)
                };
                break;
        }
        return _body;
    }

    // 格式化 请求Body 参数（用于脚本使用）
    formatDisplayRequestBodys(target: any) {
        let _body: any = {
            'request_bodys': {},
            'raw': {
                'mode': 'none'
            }
        };

        let arr = _.cloneDeep(_.get(target, 'request.body.parameter'));

        switch (_.get(target, 'request.body.mode')) {
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
                    let _raw: Array<any> = [];
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
                    let _raw: Array<any> = [];
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

    // 响应时间点
    resposneAt() {
        var time: any = new Date();
        var h: any = time.getHours();
        h = h < 10 ? '0' + h : h;
        var m: any = time.getMinutes();
        m = m < 10 ? '0' + m : m;
        var s: any = time.getSeconds();
        s = s < 10 ? '0' + s : s;
        return h + ':' + m + ':' + s;
    }


    // 不区分大小写的 _.get
    getCaseInsensitive(object: any, keyToFind: any) {
        try {
            // 先将要查找的键转换成小写
            const lowerKey: any = keyToFind.toLowerCase();

            if (!_.isObject(object)) {
                return undefined;
            }

            // 在对象的所有键中查找
            for (const key in object) {
                if (key.toLowerCase() === lowerKey) {
                    return object[key];
                }
            }
        } catch (e) { }

        // 如果没有找到，返回undefined
        return undefined;
    }

    // 不区分大小写的 _.set
    setCaseInsensitive(obj: any, path: any, value: any) {
        if (typeof path === 'string') {
            // 把点路径转换为数组形式，以处理嵌套对象
            path = _.toPath(path);

            // 变量lastKey持有最后一个键，我们需要在后面步骤中用它来设置值
            const lastKey: any = path.pop();

            // 寻找路径中匹配的键，不区分大小写
            path = path.map((segment: any) => {
                const key: any = Object.keys(obj).find(
                    objKey => objKey.toLowerCase() === segment.toLowerCase()
                );
                return key || segment;
            });

            // 把最后一个键加回到路径中
            path.push(lastKey);

            // 使用lodash的_.set来设置值
            _.set(obj, path, value);
        } else {
            // 如果path不是字符串，假设它是正确的路径数组
            _.set(obj, path, value);
        }
    }

    // 生成digest认证头
    getDigestAuthString(target: any, method: any, fullPath: any, digest: any) {
        let ha1: any = '', ha2: any = '', response: any = '', hashFunc: any = CryptoJS.MD5;
        let entityBody = _.get(this.formatRequestBodys(target), 'body') || '';

        if (digest.algorithm == 'MD5' || digest.algorithm == 'MD5-sess') {
            hashFunc = CryptoJS.MD5;
        } else if (digest.algorithm == 'SHA-256' || digest.algorithm == 'SHA-256-sess') {
            hashFunc = CryptoJS.SHA256;
        } else if (digest.algorithm == 'SHA-512' || digest.algorithm == 'SHA-512-sess') {
            hashFunc = CryptoJS.SHA512;
        }

        let cnonce: any = digest.cnonce == '' ? 'apipost' : digest.cnonce;

        if (digest.algorithm.substr(-5) == '-sess') {
            ha1 = hashFunc(hashFunc(digest.username + ':' + digest.realm + ':' + digest.password).toString() + ':' + digest.nonce + ':' + cnonce).toString();
        } else {
            ha1 = hashFunc(digest.username + ':' + digest.realm + ':' + digest.password).toString();
        }

        if (digest.qop != 'auth-int') {
            ha2 = hashFunc(method + ':' + fullPath).toString();
        } else if (digest.qop == 'auth-int') {
            ha2 = hashFunc(method + ':' + fullPath + ':' + hashFunc(entityBody).toString()).toString();
        }

        if (digest.qop == 'auth' || digest.qop == 'auth-int') {
            response = hashFunc(ha1 + ':' + digest.nonce + ':' + (digest.nc || '00000001') + ':' + cnonce + ':' + digest.qop + ':' + ha2).toString();
        } else {
            response = hashFunc(ha1 + ':' + digest.nonce + ':' + ha2).toString();
        }

        return "Digest username=\"" + digest.username + "\", realm=\"" + digest.realm + "\", nonce=\"" + digest.nonce + "\", uri=\"" + fullPath + "\", algorithm=\"" + digest.algorithm + "\", qop=\"" + digest.qop + "\",nc=" + (digest.nc || '00000001') + ", cnonce=\"" + cnonce + "\", response=\"" + response + "\", opaque=\"" + digest.opaque + "\"";
    }

    //生成ntlm认证头
    getNTLMAuthString(target: any, type2msg: any, ntlm: any) {
        const { uri } = this.setQueryString(target.request.url, this.formatQueries(target.request.query.parameter));
        return ntlm.createType3Message(type2msg, {
            url: uri,
            username: ntlm.username,
            password: ntlm.password,
            workstation: ntlm.workstation,
            domain: ntlm.domain
        })
    }

    // 处理 响应参数
    async formatResponseData(error: any, response: any, target: any) {
        const uri: any = _.get(response, 'request.options.url');
        const protocol: any = _.get(uri, 'protocol') == 'https:' ? 'https' : 'http';
        const target_id: any = _.get(target, 'target_id');
        const requestBody: any = this.formatDisplayRequestBodys(target);

        const result: any = {
            error: error,
            request: {
                "url": String(uri),
                "uri": uri,
                "method": _.get(response, 'request.options.method'),
                "timeout": parseInt(_.get(response, 'request.options.timeout.request')) || 0,
                "contentType": this.getCaseInsensitive(_.get(response, 'request.options.headers') || {}, 'content-type') || 'none',
                "header": _.map(_.get(response, 'request.options.headers'), (value: any, key: any) => ({ key, value })),
                "proxy": _.get(response, `request.options.agent.${protocol}.proxyOptions`) || null,
                "httpVersion": _.get(response, 'httpVersion'),
                "request_headers": _.get(response, 'request.options.headers'),
                "request_bodys": _.get(requestBody, 'raw'),
                "body": _.get(requestBody, 'raw')
            },
            response: {}
        }
        _.assign(result, {
            response: {
                "target_id": target_id,
                "responseTime": _.get(response, 'timings.phases.total') || '0.00',
                "responseSize": _.round((this.getCaseInsensitive(_.get(response, 'headers'), 'content-length') || String(_.get(response, 'body')).length) / 1024, 2),
                "resposneAt": this.resposneAt(),
                "netWork": {
                    "agent": _.get(response, `request.options.agent.${protocol}.proxyOptions`) || null,
                    "address": {
                        "remote": {
                            "address": _.get(response, 'ip')
                        }
                    }
                },
                "status": _.get(response, 'statusMessage') || 'OK',
                "code": _.get(response, 'statusCode') || 200,
                "timingPhases": _.get(response, 'timings.phases') || {},
                "resHeaders": getObjFromRawHeaders(_.get(response, 'rawHeaders') || []) || {},
                "headers": getObjFromRawHeaders(_.get(response, 'rawHeaders') || []) || {},
                "header": _.map(getObjFromRawHeaders(_.get(response, 'rawHeaders') || []) || {}, (value: any, key: any) => ({ key, value })) || [],
                "rawCookies": [],
                "resCookies": [],
                "cookies": {},
                "rawBody": String(_.get(response, 'body')) || '',
                "stream": {
                    "type": "Buffer",
                    "data": _.get(response, 'body')
                },
                "fitForShow": "Monaco",
                "resMime": {
                    "ext": "json",
                    "mime": "application/json"
                },
                "raw": {
                    "status": _.get(response, 'statusMessage'),
                    "responseTime": _.get(response, 'timings.phases.total'),
                    "type": "json",
                    "responseText": String(_.get(response, 'body'))
                },
                "json": {},
                "filename": ``
            }
        });

        // 设置 cookie
        if (_.isArray(this.getCaseInsensitive(_.get(response, 'headers'), 'set-cookie'))) {
            const rawCookies: any = setCookie.parse(this.getCaseInsensitive(_.get(response, 'headers'), 'set-cookie'));
            _.assign(result.response, {
                rawCookies,
                resCookies: rawCookies
            })
        }

        if (_.isArray(_.get(result, `response.rawCookies`))) {
            _.assign(result.response, {
                cookies: _.reduce(_.get(result, `response.rawCookies`), (result: any, cookie: any) => {
                    result[cookie.name] = cookie.value;
                    return result;
                }, {})
            })
        }

        // 设置json
        try {
            _.assign(result.response, {
                json: JSON5.parse(String(_.get(response, 'body')))
            });
        } catch (e) { }

        // 响应类型
        const resMime: any = {
            "ext": "json",
            "mime": "application/json"
        }

        try {
            if (isSvg(_.get(response, 'body').toString())) {
                _.assign(resMime, {
                    ext: "svg",
                    mime: "image/svg+xml"
                })

                _.assign(result.response, {
                    fitForShow: 'Image'
                })
            } else {
                const fileTypeMime: any = await FileType.fromBuffer(_.get(response, 'body'))

                if (_.isObject(fileTypeMime)) {
                    _.assign(resMime, fileTypeMime)

                    if (isImage(`test.${resMime.ext}`)) {
                        _.assign(result.response, {
                            fitForShow: 'Image'
                        })
                    } else if (resMime.ext == 'pdf') {
                        _.assign(result.response, {
                            fitForShow: 'Pdf'
                        })
                    } else {
                        _.assign(result.response, {
                            fitForShow: 'Other'
                        })
                    }
                } else {
                    const contentType: any = this.getCaseInsensitive(_.get(response, 'headers') || {}, 'content-type') || ''

                    if (!_.isEmpty(contentType)) {
                        _.assign(resMime, {
                            ext: mime.getExtension(contentType),
                            mime: mime.getType(mime.getExtension(contentType))
                        })
                    } else {
                        const ext = ATools.isJson(result.response.rawBody) ? 'json' : ATools.isJsonp(result.response.rawBody) ? 'jsonp' : 'html';
                        _.assign(resMime, {
                            ext: ext,
                            mime: mime.getType(ext) || 'application/jsonp'
                        })
                    }

                    _.assign(result.response, {
                        fitForShow: 'Monaco'
                    })
                }
            }
        } catch (e) { }

        _.assign(result.response, {
            resMime
        })

        // 缓存文件名
        if (!_.isEmpty(_.get(process, 'versions.electron'))) {
            let fileName: any = _.get(this.getCaseInsensitive(_.get(response, 'headers') || {}, 'content-disposition'), 'parameters.filename')

            try {
                if (_.isString(fileName)) {
                    fileName = decodeURIComponent(fileName)
                } else {
                    fileName = `${target_id}.${_.get(result, 'response.resMime.ext')}`
                }
            } catch (e) { }

            try {
                fileName = path.join(path.resolve(this.getCachePath()), fileName)
                fs.writeFileSync(fileName, _.get(response, 'body'));

                _.assign(result.response, {
                    filename: fileName
                })
            } catch (e) { }
        }

        // 重置响应内容
        _.set(result, 'response.raw.type', _.get(result, 'response.resMime.ext'));

        if (_.get(result, 'response.fitForShow') != 'Monaco') {
            _.set(result, 'response.rawBody', '');
            _.set(result, 'response.raw.responseText', '');
        }

        return new Promise((resolve) => {
            resolve(result)
        })
    }

    // 取消发送
    abort() {
        try {
            if (_.isObject(this.requestLink) && _.isFunction(this.requestLink.cancel)) {
                this.requestLink.cancel();
            }
        } catch (e) { }
    }

    // 发送
    async request(target: any, extra_headers: any) {
        // 开始重写发送逻辑
        const that: any = this;

        return new Promise(async (reslove, reject) => {
            if (!Validator(target, that.jsonschema).valid) {
                console.error({
                    target,
                    status: 'error'
                })
                reject(that.ConvertResult('error', '错误的请求数据格式，请联系 Apipost 技术人员协助处理。'));
                // 改造 ConvertResult 捕获错误数据写到日志
            } else {
                // 请求URL的对象
                const request_urls: any = new UrlParse(_.get(target, 'request.url'));
                if (_.isEmpty(request_urls?.port)) {
                    _.assign(request_urls, {
                        port: request_urls?.protocol == 'https:' ? 443 : 80
                    })
                }

                // 获取认证请求头
                const authHeaders: any = that.createAuthHeaders(target);

                // 初始化请求配置
                const options = {
                    throwHttpErrors: false,
                    method: _.get(target, 'method') || 'GET',
                    allowGetBody: true,
                    headers: { ...authHeaders },
                    responseType: "buffer",
                    ignoreInvalidCookies: true,
                    decompress: true,
                    http2: false,
                    // 以下为重试设置
                    retry: 0,
                    // 以下为重定向设置
                    followRedirect: false,
                    methodRewriting: false,
                    maxRedirects: 10
                }

                // 设置超时时间
                if (parseInt(_.get(that.option, 'timeout')) > 0) {
                    _.assign(options, {
                        timeout: parseInt(_.get(that.option, 'timeout'))
                    })
                }

                // 是否开启重定向
                if (parseInt(_.get(that.option, 'followRedirect')) > 0) {
                    _.assign(options, {
                        followRedirect: true
                    })

                    if (parseInt(_.get(that.option, 'methodRewriting')) > 0) {
                        _.assign(options, {
                            methodRewriting: true
                        })
                    }

                    if (parseInt(_.get(that.option, 'maxrequstloop')) > 0) {
                        _.assign(options, {
                            maxRedirects: parseInt(_.get(that.option, 'maxrequstloop'))
                        })
                    }
                }

                // 设置开启 http2
                const protocol = _.get(target, 'request.protocol')
                if (protocol == 'http/2') {
                    _.assign(options, {
                        http2: true
                    })
                }

                // 设置安全证书
                const https: any = {
                    rejectUnauthorized: false
                };

                // ca 证书
                if (_.get(that.option, 'ca_cert.open') > 0) {
                    let cacert_path = _.get(that.option, 'ca_cert.path');
                    let cacert_base64 = String(_.get(that.option, 'ca_cert.base64')).replace(/^data:.*?;base64,/, '');

                    if (isBase64(cacert_base64, { allowEmpty: false })) {
                        _.assign(https, {
                            certificateAuthority: Buffer.from(cacert_base64, 'base64')
                        })
                    } else {
                        if (_.isString(cacert_path) && !_.isEmpty(cacert_path)) {
                            try {
                                fs.accessSync(cacert_path)

                                _.assign(https, {
                                    certificateAuthority: fs.readFileSync(cacert_path)
                                })

                            } catch (e) { }
                        }
                    }
                }

                // 客户端证书
                try {
                    if (_.isObject(_.get(that.option, 'client_cert'))) {
                        let cert: any = _.find(_.get(that.option, 'client_cert'), (item: any) => {
                            let cert_urls: any = new UrlParse(item?.HOST)

                            if (request_urls.protocol == 'http://' && request_urls.port == '') {
                                request_urls.port = 80;
                            }

                            if (cert_urls.protocol == 'http://' && cert_urls.port == '') {
                                cert_urls.port = 80;
                            }

                            if (request_urls.protocol == 'https://' && request_urls.port == '') {
                                request_urls.port = 443;
                            }

                            if (cert_urls.protocol == 'https://' && cert_urls.port == '') {
                                cert_urls.port = 443;
                            }

                            return request_urls.protocol == cert_urls.protocol && request_urls.hostname == cert_urls.hostname && request_urls.port == cert_urls.port
                        });

                        if (_.isObject(cert) && !_.isEmpty(cert)) {
                            _.forEach({ key: "KEY", pfx: "PFX", certificate: "CRT" }, function (cp: any, key: any) {
                                let _path: any = _.get(cert, `${cp}.FILE_URL`);
                                let _base64: any = String(_.get(cert, `${cp}.FILE_BASE64`)).replace(/^data:.*?;base64,/, '');

                                if (isBase64(_base64, { allowEmpty: false })) {
                                    https[key] = Buffer.from(_base64, 'base64')
                                } else {
                                    if (_.isString(_path) && !_.isEmpty(_path)) {
                                        try {
                                            fs.accessSync(_path)
                                            https[key] = fs.readFileSync(_path)

                                        } catch (e) { }
                                    }
                                }
                            });

                            let passphrase: any = _.get(cert, 'PASSWORD');

                            if (_.isString(passphrase) && !_.isEmpty(passphrase)) {
                                _.assign(https, {
                                    passphrase
                                })
                            }
                        }
                    }
                } catch (e) { }

                _.assign(options, {
                    https
                })

                // 当请求不是http2类型时，设置代理。http2 暂时不支持代理。
                if (options?.http2 == false) {
                    let proxy: any = {}, host: any = '', port: any = 0;

                    if (_.get(that.option, 'proxy.type') == 1) { // 自定义代理
                        let match: any = _.get(that.option, 'proxy.auth.host').match(/(([^:]+):(\d+))/);

                        if (_.isArray(match) && parseInt(match[3], 10) > 0) {
                            host = match[2];
                            port = parseInt(match[3]);
                        }

                        // 检查host 是不是在 bypass 里面
                        let bypass = _.get(that.option, 'proxy.bypass');

                        if (_.isString(bypass)) {
                            bypass = bypass.split(',')
                        }

                        let bypassMatch = _.find(bypass, function (o: any) {
                            return minimatch(_.toLower(request_urls?.host), o)
                        })

                        if (bypassMatch) {
                            host = '';
                            port = 0;
                        } else {
                            // 检查当前协议是否匹配 protocol
                            let protocols = _.get(that.option, 'proxy.auth.protocol');

                            if (_.isString(protocols)) {
                                protocols = protocols.split(",")
                            }

                            let protocolMatch = _.find(protocols, function (o: any) {
                                return _.toLower(request_urls?.protocol) == `${o}:`
                            })

                            if (!protocolMatch) {
                                host = '';
                                port = 0;
                            }
                        }
                    } else if (_.get(that.option, 'proxy.type') == -1) { // 获取系统代理
                        let no_proxy: any = _.isString(_.get(process, 'env.NO_PROXY')) && _.get(that.option, 'proxy.envfirst') > 0 ? String(_.get(process, 'env.NO_PROXY')).split(",") : []

                        // NO_PROXY 未设置或者 当前host 不在NO_PROXY
                        if (_.isEmpty(no_proxy) || _.isUndefined(_.find(no_proxy, function (o: any) {
                            return minimatch(_.toLower(request_urls?.host), o)
                        }))) {
                            if (_.get(that.option, 'proxy.envfirst') > 0 || _.isEmpty(_.get(process, 'versions.electron'))) {
                                const env_proxy: any = String(request_urls?.protocol == 'https:' ? _.get(process, 'env.HTTPS_PROXY') : _.get(process, 'env.HTTP_PROXY'));
                                if (!_.isEmpty(env_proxy)) {
                                    let env_proxy_parse: any = new UrlParse(env_proxy);
                                    host = env_proxy_parse?.hostname || '';
                                    port = parseInt(env_proxy_parse?.port, 10) > 0 ? parseInt(env_proxy_parse?.port, 10) : 0;
                                }
                            } else if (!_.isEmpty(_.get(process, 'versions.electron'))) {
                                try {
                                    let value: any = await require('electron').session.defaultSession.resolveProxy(_.get(target, 'request.url'));
                                    let match: any = value.match(/PROXY (([^:]+):(\d+))/);

                                    if (_.isObject(match) && _.isString(match[2]) && !_.isEmpty(match[2]) && parseInt(match[3], 10) > 0) {
                                        host = match[2];
                                        port = parseInt(match[3], 10)
                                    }
                                } catch (e) { }
                            }
                        }
                    }

                    if (!_.isEmpty(host) && port > 0) {
                        _.assign(proxy, {
                            host,
                            port
                        })

                        if (_.get(that.option, 'proxy.auth.authenticate') > 0) {
                            if (_.get(that.option, 'proxy.auth.username') != '') {
                                _.assign(proxy, {
                                    proxyAuth: `${_.get(that.option, 'proxy.auth.username')}:${_.get(that.option, 'proxy.auth.password')}`
                                })
                            }
                        }

                        if (request_urls?.protocol == 'https:') {
                            _.assign(options, {
                                agent: {
                                    https: tunnel.httpsOverHttp({
                                        proxy
                                    })
                                }
                            })
                        } else {
                            _.assign(options, {
                                agent: {
                                    http: tunnel.httpsOverHttp({
                                        proxy
                                    })
                                }
                            })
                        }
                    }
                }

                // 设置 请求query
                const searchParams: any = {};
                _.forEach(_.get(target, 'request.query.parameter'), (item: any) => {
                    if (item.is_checked > 0 && !_.isEmpty(item.key)) {
                        searchParams[item.key] = item.value;
                    }
                })

                if (!_.isEmpty(searchParams)) {
                    _.assign(options, {
                        searchParams
                    })
                }

                // 设置请求体
                const formatRequestBodys: any = that.formatRequestBodys(target), requestError: any = _.get(formatRequestBodys, 'error'), requestContentType: any = _.get(formatRequestBodys, 'header'), requestBody: any = _.get(formatRequestBodys, 'body');

                if (!_.isEmpty(requestError)) {
                    reject(that.ConvertResult('error', `${requestError}`));
                }

                if (!_.isEmpty(requestContentType)) {
                    let ctKey: any = _.find(_.keys(options.headers), function (h: any) { return _.toLower(h) == 'content-type'; }) || 'content-type';
                    _.set(options, `headers.${ctKey}`, requestContentType['content-type'])
                }

                if (!_.isEmpty(requestBody)) {
                    _.assign(options, {
                        body: requestBody
                    })
                }

                // hook
                _.assign(options, {
                    hooks: {
                        // 处理添加请求头
                        beforeRequest: [
                            (options: any) => {
                                _.forEach({
                                    "User-Agent": `ApipostRequest/${module.exports?.version} (https://www.apipost.cn)`,
                                    ...that.formatRequestHeaders(_.get(target, 'request.header.parameter'), _.get(target, 'request.body.mode')),
                                    ...extra_headers

                                }, function (value: any, key: any) {
                                    _.unset(options, `headers.${_.toLower(key)}`)
                                    that.setCaseInsensitive(options, `headers.${key}`, value)
                                });
                            }
                        ],
                        // 处理一些认证逻辑
                        afterResponse: [
                            (response: any, retryWithMergedOptions: any) => {
                                if (Number(response?.statusCode) == 401) {
                                    const requestOptions = _.get(response, 'request.options');
                                    const wwwAuthenticate = that.getCaseInsensitive(_.get(response, 'headers'), 'www-authenticate');

                                    if (_.isString(wwwAuthenticate) && wwwAuthenticate != '') {
                                        try {
                                            const init_parsed = new parsers.WWW_Authenticate(that.getCaseInsensitive(_.get(response, 'request.options.headers'), 'authorization') || '');
                                            const parsed = new parsers.WWW_Authenticate(wwwAuthenticate);
                                            const fullUri = request_urls.href.substr(request_urls.origin.length);

                                            if (_.toLower(parsed?.scheme) == 'digest') {
                                                that.setCaseInsensitive(requestOptions, 'headers.authorization', `${that.getDigestAuthString(target, options?.method, fullUri, _.assign(_.get(target, 'request.auth.digest') || {}, init_parsed?.parms, parsed?.parms))
                                                    }`);

                                                return retryWithMergedOptions(requestOptions)
                                            } else if (_.toLower(parsed?.scheme) == 'ntlm' || wwwAuthenticate.includes('NTLM')) {
                                                that.setCaseInsensitive(requestOptions, 'headers.authorization', `${that.getNTLMAuthString(target, ntlm.parseType2Message(wwwAuthenticate), _.get(target, 'request.auth.ntlm'))
                                                    }`);

                                                return retryWithMergedOptions(requestOptions)
                                            }
                                        } catch (e) { }
                                    }
                                }

                                return response;
                            }
                        ]
                    }
                })

                // 实际发送
                const request_urls_clone = _.cloneDeep(request_urls);
                request_urls_clone.set("query", '');
                request_urls_clone.set("hash", '');

                // 发送
                that.requestLink = got(request_urls_clone.toString(), options).then(async (response: any) => {
                    reslove(that.ConvertResult('success', 'success', await that.formatResponseData(null, response, target)))
                }).catch(async (error: any) => {
                    reject(that.ConvertResult('error', `${String(error)}[${error?.code}]`, await that.formatResponseData(`${String(error)}[${error?.code}]`, error.response, target)))
                });
            }
        })
        // 完成重写发送逻辑
    };
}

export default ApipostRequest;
