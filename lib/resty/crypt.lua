local random = require "resty.random"
local str = require "resty.string"
local aes = require "resty.aes_pad"
local bit = require "bit"
local resty_sha1 = require "resty.sha1"
local setmetatable, assert = setmetatable, assert
local str_char, str_sub, str_byte, str_format = string.char, string.sub, string.byte, string.format
local decode_base64, encode_base64 = ngx.decode_base64, ngx.encode_base64

local _M = { _VERSION = '0.2' }

local mt = { __index = _M }

local function pack_text_len(text_len)
    local band, rshift, mask = bit.band, bit.rshift, 0xff
    return str_char(
        band(rshift(text_len, 24), mask),
        band(rshift(text_len, 16), mask),
        band(rshift(text_len, 8), mask),
        band(text_len, mask)
    )
end

local function unpack_text_len(text_len)
    local bor, lshift = bit.bor, bit.lshift
    local a, b, c, d = str_byte(text_len, 1, 4)
    return bor(lshift(a, 24), lshift(b, 16), lshift(c, 8), d), 1 + 4
end

local function pkcs7_encode(text)
    local PAD_BLOCK_LENGTH = 32
    local amount_to_pad = PAD_BLOCK_LENGTH - (#text % PAD_BLOCK_LENGTH)

    if amount_to_pad == 0 then
        amount_to_pad = PAD_BLOCK_LENGTH
    end
    local str_pad = str_char(amount_to_pad):rep(amount_to_pad)

    return text .. str_pad
end

local function pkcs7_decode(text)
    local pad = str_byte(text, #text - 1)

    if (pad < 1 or pad > 32) then
        pad = 0
    end

    return str_sub(text, 1, #text - pad);
end

function _M.new (self, token, aes_key, app_id)
    local aes_key = decode_base64(aes_key .. "=")
    local cipher = aes.cipher(256, "cbc")
    local iv = str_sub(aes_key, 0, 16)

    return setmetatable({token = token, aes_key = aes_key, app_id = app_id, cipher = cipher, iv = iv}, mt)
end

function _M.get_sha1 (self, sha1_table)
    local tb_sort, tb_join = table.sort, table.concat
    tb_sort(sha1_table)

    local to_sha1 = tb_join(sha1_table)

    local sha1 = resty_sha1:new()
    sha1:update(to_sha1)

    return str.to_hex(sha1:final())
end

function _M.decrypt (self, encrypted)
    local ciphertext_dec = decode_base64(encrypted)

    if ciphertext_dec == nil then
        return nil
    end

    local aes_crypt = assert(
        aes:new(self.aes_key, nil, self.cipher, {iv = self.iv})
    )
    aes_crypt:set_padding(0)

    local text = aes_crypt:decrypt(ciphertext_dec)
    text = pkcs7_decode(str_sub(text, 17, #text))

    local xml_len = unpack_text_len(str_sub(text, 1, 4))

    return str_sub(text, 4 + 1, xml_len + 4)
end

function _M.encrypt (self, text, timestamp, nonce)
    local prefix = str.to_hex(random.bytes(8, true))

    text = prefix .. pack_text_len(#text) .. text .. self.app_id
    text = pkcs7_encode(text)

    local aes_crypt = assert(
        aes:new(self.aes_key, nil, self.cipher, {iv = self.iv})
    )
    aes_crypt:set_padding(0)

    local encrypted = encode_base64(aes_crypt:encrypt(text))
    local signature = self:get_sha1({self.token, timestamp, nonce, encrypted})
    local xml_content = "<xml><Encrypt><![CDATA[%s]]></Encrypt><MsgSignature><![CDATA[%s]]></MsgSignature><TimeStamp>%s</TimeStamp><Nonce><![CDATA[%s]]></Nonce></xml>";

    return str_format(xml_content, encrypted, signature, timestamp, nonce)
end

return _M
