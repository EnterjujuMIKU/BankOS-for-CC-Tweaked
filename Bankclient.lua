-- ====================================================
-- bankclient.lua - client de l'API Rednet de BankOS v2
--
-- Installation : copiez ce fichier ET bank_network.key (genere par le
-- serveur au premier lancement) sur l'ordinateur de la boutique.
--
-- Exemple :
--   local bank = require("bankclient")
--   bank.init()                                   -- ouvre les modems + charge la cle
--   local ok, msg = bank.pay("Steve", "1234", 250, "BoutiqueBob",
--                            { memo = "Diamant x2", source = "balance" })
--   -- source = "balance" (compte, defaut) ou "wallet" (argent sur la carte)
-- ====================================================
local PROTOCOL = "BANKOS_API"
local TIMEOUT  = 5
local band, bor, bxor, bnot = bit32.band, bit32.bor, bit32.bxor, bit32.bnot
local rshift, rrotate = bit32.rshift, bit32.rrotate
local MOD32 = 4294967296

-- CRYPTO_BEGIN
local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function u32be(n)
    return string.char(band(rshift(n, 24), 255), band(rshift(n, 16), 255), band(rshift(n, 8), 255), band(n, 255))
end

local function sha256(msg)
    local len = #msg
    local bits = len * 8
    msg = msg .. "\128" .. string.rep("\0", (55 - len) % 64)
        .. u32be(math.floor(bits / MOD32)) .. u32be(bits % MOD32)
    local H = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
    local w = {}
    for chunk = 1, #msg, 64 do
        for i = 0, 15 do
            local a, b, c, d = msg:byte(chunk + i * 4, chunk + i * 4 + 3)
            w[i] = ((a * 256 + b) * 256 + c) * 256 + d
        end
        for i = 16, 63 do
            local w15, w2 = w[i - 15], w[i - 2]
            local s0 = bxor(rrotate(w15, 7), rrotate(w15, 18), rshift(w15, 3))
            local s1 = bxor(rrotate(w2, 17), rrotate(w2, 19), rshift(w2, 10))
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) % MOD32
        end
        local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
        for i = 0, 63 do
            local S1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
            local ch = bxor(band(e, f), band(bnot(e), g))
            local t1 = (h + S1 + ch + K[i + 1] + w[i]) % MOD32
            local S0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
            local maj = bxor(band(a, b), band(a, c), band(b, c))
            local t2 = (S0 + maj) % MOD32
            h = g; g = f; f = e; e = (d + t1) % MOD32
            d = c; c = b; b = a; a = (t1 + t2) % MOD32
        end
        H[1] = (H[1] + a) % MOD32; H[2] = (H[2] + b) % MOD32
        H[3] = (H[3] + c) % MOD32; H[4] = (H[4] + d) % MOD32
        H[5] = (H[5] + e) % MOD32; H[6] = (H[6] + f) % MOD32
        H[7] = (H[7] + g) % MOD32; H[8] = (H[8] + h) % MOD32
    end
    local out = {}
    for i = 1, 8 do out[i] = u32be(H[i]) end
    return table.concat(out)
end

local function toHex(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function fromHex(h)
    if type(h) ~= "string" or #h % 2 ~= 0 or h:find("%X") then return nil end
    return (h:gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end))
end

local function hmac(key, msg)
    if #key > 64 then key = sha256(key) end
    key = key .. string.rep("\0", 64 - #key)
    local ipad, opad = {}, {}
    for i = 1, 64 do
        local kb = key:byte(i)
        ipad[i] = string.char(bxor(kb, 0x36))
        opad[i] = string.char(bxor(kb, 0x5c))
    end
    return sha256(table.concat(opad) .. sha256(table.concat(ipad) .. msg))
end

local function safeEqual(a, b)
    if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then return false end
    local diff = 0
    for i = 1, #a do diff = bor(diff, bxor(a:byte(i), b:byte(i))) end
    return diff == 0
end

-- Generateur pseudo-aleatoire (CC n'a pas de vraie source d'entropie) :
-- on melange heure, horloge, math.random et le timing des actions du joueur.
math.randomseed(os.epoch("utc") % 2147483647 + math.floor(os.clock() * 1000))
local entropyState = sha256(tostring(os.epoch("utc")) .. "|" .. tostring(os.clock()) .. "|"
    .. tostring({}) .. "|" .. tostring(os.getComputerID()) .. "|" .. tostring(math.random(0, 1073741823)))

local function mixEntropy(extra)
    entropyState = sha256("M" .. entropyState .. tostring(extra) .. tostring(os.epoch("utc")) .. tostring(os.clock()))
end

local function randomBytes(n)
    local out, have, ctr = {}, 0, 0
    while have < n do
        ctr = ctr + 1
        entropyState = sha256("S" .. entropyState .. tostring(math.random(0, 1073741823))
            .. tostring(os.epoch("utc")) .. tostring(os.clock()) .. ctr)
        out[#out + 1] = sha256("O" .. entropyState)
        have = have + 32
    end
    return table.concat(out):sub(1, n)
end

local function xorStr(a, b)
    local out = {}
    for i = 1, #a do out[i] = string.char(bxor(a:byte(i), b:byte(i))) end
    return table.concat(out)
end

local function keystream(encKey, nonce, len)
    local blocks = {}
    for i = 0, math.ceil(len / 32) - 1 do
        blocks[#blocks + 1] = sha256(encKey .. nonce .. u32be(i))
    end
    return table.concat(blocks)
end

-- Chiffrement authentifie : nonce(16) .. XOR(keystream SHA-256 en mode compteur) .. HMAC-SHA256(32)
-- Toute modification du message est detectee. Sortie en hexadecimal (ASCII sur).
local function encrypt(plain, master)
    local ek, mk = sha256("ENC|" .. master), sha256("MAC|" .. master)
    local nonce = randomBytes(16)
    local ct = xorStr(plain, keystream(ek, nonce, #plain))
    return toHex(nonce .. ct .. hmac(mk, nonce .. ct))
end

local function decrypt(hex, master)
    local raw = fromHex(hex)
    if not raw or #raw < 48 then return nil end
    local ek, mk = sha256("ENC|" .. master), sha256("MAC|" .. master)
    local nonce, ct, tag = raw:sub(1, 16), raw:sub(17, -33), raw:sub(-32)
    if not safeEqual(hmac(mk, nonce .. ct), tag) then return nil end
    return xorStr(ct, keystream(ek, nonce, #ct))
end

local M = {}
local NET_KEY

function M.init(keyFile)
    local f = fs.open(keyFile or "bank_network.key", "r")
    if not f then error("bank_network.key introuvable", 2) end
    local k = (f.readAll() or ""):gsub("%s", "")
    f.close()
    NET_KEY = k
    for _, n in ipairs(peripheral.getNames()) do
        if peripheral.getType(n) == "modem" and not rednet.isOpen(n) then rednet.open(n) end
    end
end

-- Retourne ok (bool), message (string), reponse complete (table)
function M.pay(account, pin, amount, target, opts)
    if not NET_KEY then M.init() end
    opts = opts or {}
    local nonce = toHex(randomBytes(16))
    local req = {
        type = "PAYMENT", ts = os.epoch("utc"), nonce = nonce,
        account = account, pin = tostring(pin), amount = amount, target = target,
        source = opts.source, memo = opts.memo,
    }
    rednet.broadcast(encrypt(textutils.serialize(req), NET_KEY), PROTOCOL)

    local timer = os.startTimer(opts.timeout or TIMEOUT)
    while true do
        local ev, a, b, c = os.pullEvent()
        if ev == "rednet_message" and c == PROTOCOL and type(b) == "string" then
            local plain = decrypt(b, NET_KEY)
            local resp = plain and textutils.unserialize(plain)
            -- la reponse doit etre authentique, recente et liee a NOTRE requete
            if type(resp) == "table" and resp.nonce == nonce and type(resp.ts) == "number"
                and math.abs(os.epoch("utc") - resp.ts) < 30000 then
                return resp.ok == true, tostring(resp.message), resp
            end
        elseif ev == "timer" and a == timer then
            return false, "Pas de reponse de la banque"
        end
    end
end

return M
