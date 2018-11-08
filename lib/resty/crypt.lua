local random = require "resty.random"
local str = require "resty.string"
local aes = require "resty.aes_pad"
local bit = require "bit"
local resty_sha1 = require "resty.sha1"
local setmetatable = setmetatable

local _M = { _VERSION = '0.2' }

local mt = { __index = _M }

local function pack_text_len(text_len)
    return string.char(
        bit.band(bit.rshift(text_len, 24), 0xff),
        bit.band(bit.rshift(text_len, 16), 0xff),
        bit.band(bit.rshift(text_len, 8), 0xff),
        bit.band(text_len, 0xff)
    )
end

local function unpack_text_len(text_len)
    local a, b, c, d = string.byte(text_len, 1, 4)
    return bit.bor(bit.lshift(a, 24), bit.lshift(b, 16), bit.lshift(c, 8), d), 1 + 4
end

local function pkcs7_encode(text)
    local amount_to_pad = 32 - (#text % 32)

    if amount_to_pad == 0 then
        amount_to_pad = 32
    end

    local padding = ""

    local pad = string.char(amount_to_pad)

    for i = 1, amount_to_pad do
        padding = padding .. pad
    end

    return text .. padding
end

local function pkcs7_decode(text)
    local pad = string.byte(text, #text - 1)

    if (pad < 1 or pad > 32) then
        pad = 0
    end

    return string.sub(text, 1, #text - pad);
end

function _M.new (self, token, aes_key, app_id)
    local aes_key = ngx.decode_base64(aes_key .. "=")
    local cipher = aes.cipher(256, "cbc")
    local iv = string.sub(aes_key, 0, 16)
    return setmetatable({token = token, aes_key = aes_key, app_id = app_id, cipher = cipher, iv = iv}, mt)
end

function _M.get_sha1 (self, sha1_table)
    local tb_sort = table.sort
    tb_sort(sha1_table)

    local tb_join = table.concat
    local to_sha1 = tb_join(sha1_table)

    local sha1 = resty_sha1:new()
    sha1:update(to_sha1)

    return str.to_hex(sha1:final())
end

function _M.decrypt (self, encrypted)
    local ciphertext_dec = ngx.decode_base64(encrypted)

    if ciphertext_dec == nil then
        return nil
    end

    local iv = string.sub(self.aes_key, 0, 16)
    local aes_crypt = assert(
        aes:new(self.aes_key, nil, self.cipher, {iv = self.iv})
    )
    aes_crypt:set_padding(0)

    local text = aes_crypt:decrypt(ciphertext_dec)
    text = pkcs7_decode(string.sub(text, 17, #text))

    local xml_len = unpack_text_len(string.sub(text, 1, 4))

    return string.sub(text, 4 + 1, xml_len + 4)
end


function _M.encrypt (self, text, timestamp, nonce)
    local prefix = str.to_hex(random.bytes(8, true))

    text = prefix .. pack_text_len(#text) .. text .. self.app_id
    text = pkcs7_encode(text)

    local aes_crypt = assert(
        aes:new(self.aes_key, nil, self.cipher, {iv = self.iv})
    )
    aes_crypt:set_padding(0)

    local encrypted = ngx.encode_base64(aes_crypt:encrypt(text))
    local signature = self:get_sha1({self.token, timestamp, nonce, encrypted})
    local xml_content = "<xml><Encrypt><![CDATA[%s]]></Encrypt><MsgSignature><![CDATA[%s]]></MsgSignature><TimeStamp>%s</TimeStamp><Nonce><![CDATA[%s]]></Nonce></xml>";

    return string.format(xml_content, encrypted, signature, timestamp, nonce)
end

return _M
