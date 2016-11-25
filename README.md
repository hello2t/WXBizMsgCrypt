# WXBizMsgCrypt

模仿[微信公众平台加密解密技术方案](https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1419318482&lang=zh_CN)
写了一个openresty 版的加密解密。

注意点：
aes.lua不是openresty 主版本的，而是用了这个[no padding](https://github.com/openresty/lua-resty-string/pull/35)

