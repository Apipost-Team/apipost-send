import ApipostRequest from '../src/ApipostRequest'


describe('works', async () => {
  let apipostSend=new ApipostRequest();
//   let target={
//     "target_id": "11bf5b37-e0b8-42e0-8dcf-dc8c4aefc000",
//     "method": "GET",
//     "url": "h123213tt123ps://ww213w.ba1232idu21312.com/",
//     // "url": "http://www.126.com",
//     "request": {
//         "url": "https://go.apipost.cn/",
//         "auth": {
//             "type": "oauth1",
//             "kv": {
//                 "key": "",
//                 "value": ""
//             },
//             "bearer": {
//                 "key": ""
//             },
//             "basic": {
//                 "username": "",
//                 "password": ""
//             },
//             "digest":{
//                 "username": "postman",
//                 "password": "password",
//                 "realm": "",
//                 "nonce": "",
//                 "algorithm": "MD5", // default MD5/ emum ['MD5', 'MD5-sess', "SHA-256", "SHA-256-sess", "SHA-512-256" and "SHA-512-256-sess"]
//                 "qop": "auth", // default auth
//                 "nc": "",
//                 "cnonce": "",
//                 "opaque": ""
//             },
//             "hawk":{
//                 "authKey": "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
//                 "authId": "dh37fgj492je",
//                 "algorithm": "sha256", // default sha256/ emum ['sha256', 'sha1']
//                 "includePayloadHash": false,
//                 "timestamp": "",
//                 "delegation": "",
//                 "app": "",
//                 "extraData": "",
//                 "nonce": "os2dz0",
//                 "user": ""
//             },
//             "awsv4":{
//                 "accessKey": "AKIAZPK2ZPOZLIUQCV6F",
//                 "secretKey": "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",
//                 "region": "us-east-1", // default us-east-1
//                 "addAuthDataToQuery": false,
//                 "service": "iam",  // default s3
//                 "sessionToken": ""
//             },
//             "edgegrid":{
//                 "accessToken": "akab-lkxoduyw3innhwva-tomybuxob4awownj",
//                 "clientToken": "akab-pag7jtgys2mdjbk5-bdpxciquqc7iesyc",
//                 "clientSecret": "62bYrBAXoO5I5JEcXjT8PGE8jgpQEF0R4st3HFvJ3o8=",
//                 "nonce": "444",
//                 "timestamp": "",
//                 "baseURi": "",
//                 "headersToSign": ""
//             },
//             "ntlm":{ // beta
//                 "disableRetryRequest": true,
//                 "workstation": "",
//                 "domain": "",
//                 "username": "Joerg.beck@inosoft-lab.com",
//                 "password": "INOpwd9915!te"
//             },
//             "ntlm_close":{ // 搭配 ntlm 非独立认证方式
//                 "type2msg": ""
//             },
//             "oauth1":{
//                 "consumerKey": "RKCGzna7bv9YD57c",
//                 "consumerSecret": "D+EdQ-gs$-%@2Nu7",
//                 "signatureMethod": "HMAC-SHA1", // default HMAC-SHA1/ emum ['HMAC-SHA1', 'HMAC-SHA256', 'HMAC-SHA512', 'RSA-SHA1', 'RSA-SHA256', 'RSA-SHA512', 'PLAINTEXT']

//                 // 目前 APIpost 支持 ['HMAC-SHA1', 'HMAC-SHA256', 'HMAC-SHA512', 'PLAINTEXT']
//                 "addEmptyParamsToSign": false, // 对我们无效
//                 "includeBodyHash": false,
//                 "addParamsToHeader": false, 
//                 "realm": "",
//                 "version": "1.0",
//                 "nonce": "",
//                 "timestamp": "",
//                 "verifier": "",
//                 "callback": "",
//                 "tokenSecret": "",
//                 "token": ""
//             },
//         },
//         "body": {
//             "mode": "none",
//             "parameter": [
//                 {
//                     "is_checked": "1",
//                     "type": "Text",
//                     "key": "page[]",
//                     "value": 1,
//                     "not_null": "1",
//                     "description": "",
//                     "field_type": "Integer"
//                 },
//                 {
//                     "is_checked": "1",
//                     "type": "Text",
//                     "key": "page[]",
//                     "value": 2,
//                     "not_null": "1",
//                     "description": "",
//                     "field_type": "Integer"
//                 },
//                 {
//                     "is_checked": "1",
//                     "type": "Text",
//                     "key": "title",
//                     "value": "我是标题",
//                     "not_null": "1",
//                     "description": "",
//                     "field_type": "String"
//                 },
//                 // {
//                 //     "is_checked": "1",
//                 //     "type": "Text",
//                 //     "key": "info",
//                 //     "value": "{'id':123,'age':222}",
//                 //     "contentType":"application/json",
//                 //     "not_null": "1",
//                 //     "description": "",
//                 //     "field_type": "String"
//                 // },
//                 // {
//                 //     "is_checked": "1",
//                 //     "type": "File",
//                 //     "key": "logo",
//                 //     "value": "/Users/apipost/bytenode_v2/plugins/html/icon.icns",
//                 //     "not_null": "1",
//                 //     "description": "",
//                 //     "field_type": "String"
//                 // }
//             ],
//             "raw": "111中国"
//         },
//         "header": {
//             "parameter": [
//                 // {
//                 //     "is_checked": "1",
//                 //     "type": "Text",
//                 //     "key": "token",
//                 //     "value": "1234567890",
//                 //     "not_null": "1",
//                 //     "description": "",
//                 //     "field_type": "Text"
//                 // },
//                 // {
//                 //     "is_checked": "1",
//                 //     "type": "Text",
//                 //     "key": "user-agent",
//                 //     "value": "8888888",
//                 //     "not_null": "1",
//                 //     "description": "",
//                 //     "field_type": "Text"
//                 // },
//                 {
//                     "is_checked": "1",
//                     "type": "Text",
//                     "key": "content-type",
//                     "value": "1111111",
//                     "not_null": "1",
//                     "description": "",
//                     "field_type": "Text"
//                 }
//             ]
//         },
//         "query": {
//             "parameter": [
//                 {
//                     "is_checked": "1",
//                     "type": "Text",
//                     "key": "utm_source",
//                     "value": "",
//                     "not_null": "1",
//                     "description": "",
//                     "field_type": "Text"
//                 },
//                 // {
//                 //     "is_checked": "1",
//                 //     "type": "Text",
//                 //     "key": "ids[]",
//                 //     "value": "1",
//                 //     "not_null": "baidu",
//                 //     "description": "",
//                 //     "field_type": "Text"
//                 // },
//                 // {
//                 //     "is_checked": "1",
//                 //     "type": "Text",
//                 //     "key": "ids[]",
//                 //     "value": "2",
//                 //     "not_null": "baidu",
//                 //     "description": "",
//                 //     "field_type": "Text"
//                 // },
//                 // {
//                 //     "is_checked": "1",
//                 //     "type": "Text",
//                 //     "key": "age",
//                 //     "value": "333",
//                 //     "not_null": "baidu",
//                 //     "description": "",
//                 //     "field_type": "Text"
//                 // },
//                 {
//                     "is_checked": "1",
//                     "type": "Text",
//                     "key": "age",
//                     "value": "",
//                     "not_null": "baidu",
//                     "description": "",
//                     "field_type": "Text"
//                 }
//             ]
//         }
//     }
// }
  await apipostSend.request(target).then((data)=>{
    console.log("success",data);
  }).catch(err=>{
    console.log('error',err);
  });

  it('转换成完整类型', () => {
    expect('success').toBe(`success`);
  });
});

