# WXBizMsgCrypt

[the WeChat Message Cryptography](https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1419318482&lang=zh_CN) in the openresty lua verison.

## aes_pad.lua

extend the [aes.lua](https://github.com/openresty/lua-resty-string) with a `set_padding` method, [discussing here](https://github.com/openresty/lua-resty-string/pull/35)

## crypt.lua

`encrypt(text, timestamp, nonce)`

`decrypt(text_encrypted)`

`get_sha1({token, timestamp, nonce, text_encrypted})`

## Synopsis

```lua
# nginx.conf:

server {
    location = /test {
        content_by_lua_block {
            local token = "pamtest"
            local aesKey = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
            local timestamp = "1409304348"
            local nonce = "xxxxxx"
            local appId = "wxb11529c136998cb6"
            local sample = "<xml><ToUserName><![CDATA[oia2Tj我是中文jewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType><![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo]]></Title><Description><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>"

            local crypt = require "resty.crypt"
            local wxmc = crypt:new(token, aesKey, appId)
            local encrypted = wxmc:encrypt(sample, timestamp, nonce)
            ngx.say("the sample encrypted: ", encrypted)

            local gsub = ngx.re.gsub
            sample = gsub(encrypted, [=[.*<Encrypt>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</Encrypt>.*]=], "$1")
            ngx.say("the sample decrypted: ", wxmc:decrypt(sample))
        }
    }
}
```

