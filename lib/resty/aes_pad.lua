-- patched
-- @see https://github.com/openresty/lua-resty-string/pull/35

local aes = require "resty.aes"
local ffi = require "ffi"
local C = ffi.C
ffi.cdef[[
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad);
]]

-- @link https://github.com/openssl/openssl/blob/master/crypto/evp/evp_enc.c#L569-L576
function aes.set_padding(self, pad)
    local encrypt_ctx, decrypt_ctx = self._encrypt_ctx, self._decrypt_ctx

    if encrypt_ctx == nil or decrypt_ctx == nil then
        return nil, "the aes instance doesn't existed"
    end

    -- @link https://github.com/openssl/openssl/blob/master/crypto/evp/evp_enc.c#L402-L410
    C.EVP_CIPHER_CTX_set_padding(encrypt_ctx, pad)

    -- @link https://github.com/openssl/openssl/blob/master/crypto/evp/evp_enc.c#L515-L523
    C.EVP_CIPHER_CTX_set_padding(decrypt_ctx, pad)

    return 1
end

return aes
