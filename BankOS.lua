-- ====================================================
-- BankOS v2 - Systeme Bancaire Securise (Monobloc + Serveur)
--   bankos              -> lance la banque
--   bankos resetadmin   -> regenere le PIN du compte admin cache
-- ====================================================

-- ---------- CONFIGURATION ----------
local ADMIN_NAME      = "ROOT-ADMIN"      -- compte cache (ID a taper pour se connecter)
local ADMIN_BALANCE   = 9999999999
local DB_FILE         = "bank.db"
local KEY_FILE        = ".bank_master.key"   -- cle de chiffrement de la base (ne jamais copier)
local NET_KEY_FILE    = "bank_network.key"   -- cle partagee avec les clients Rednet
local LEGACY_DB       = "bank_data.txt"      -- ancienne base (migration automatique)
local LEGACY_KEY      = "CraftBank_Secret_Key_2026"
local PROTOCOL        = "BANKOS_API"

local PIN_ROUNDS      = 100      -- iterations du hachage de PIN
local PIN_MIN_LEN     = 4
local LOCK_AFTER      = 3        -- essais rates avant verrouillage
local LOCK_BASE_MS    = 60000    -- 1 min, double a chaque echec supplementaire (max 1h)
local IDLE_TIMEOUT_MS = 60000    -- deconnexion auto de l'ATM
local API_WINDOW_MS   = 30000    -- fenetre anti-rejeu Rednet
local API_MAX_AMOUNT  = 10000000
local HISTORY_ACCOUNT = 12
local HISTORY_GLOBAL  = 50

local LOAN_MAX = 10000000
local LOAN_TIERS = {             -- {montant max, taux}
    { max = 1000,     rate = 0.01 },
    { max = 5000,     rate = 0.03 },
    { max = 20000,    rate = 0.05 },
    { max = 100000,   rate = 0.10 },
    { max = 1000000,  rate = 0.20 },
    { max = 10000000, rate = 0.40 },
}

local function loanRate(amount)
    for _, t in ipairs(LOAN_TIERS) do
        if amount <= t.max then return t.rate end
    end
    return LOAN_TIERS[#LOAN_TIERS].rate
end

-- ====================================================
-- 1. CRYPTOGRAPHIE : SHA-256, HMAC, chiffrement authentifie
-- ====================================================
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
-- CRYPTO_END

-- PIN : hash sale + iterations
local function hashPin(pin, salt)
    local h = sha256(salt .. "|" .. pin)
    for _ = 1, PIN_ROUNDS do h = sha256(h .. salt .. pin) end
    return toHex(h)
end

local function hashCardId(id) return toHex(sha256("CARD|" .. id)) end

local function fmt(n)
    local s = string.format("%.0f", n)
    local r = s:reverse()
    r = r:gsub("(%d%d%d)", "%1 ")
    s = r:reverse()
    s = s:gsub("^ ", "")
    return s
end

-- ====================================================
-- 2. CLES
-- ====================================================
local MASTER_KEY, CARD_KEY, NET_KEY

local function gatherEntropy()
    term.clear(); term.setCursorPos(1, 1)
    print("Premiere installation : generation des cles.")
    print("Tapez 30 touches au hasard, a rythme irregulier :")
    for i = 1, 30 do
        local _, key = os.pullEvent("key")
        mixEntropy(tostring(key) .. ":" .. i)
        write("*")
    end
    print()
end

local function loadKey(path)
    if fs.exists(path) then
        local f = fs.open(path, "r")
        local k = (f.readAll() or ""):gsub("%s", "")
        f.close()
        if #k < 32 then error("Fichier de cle invalide : " .. path, 0) end
        return k
    end
    local k = toHex(randomBytes(32))
    local f = fs.open(path, "w")
    f.write(k); f.close()
    return k
end

local function initKeys()
    if not fs.exists(KEY_FILE) or not fs.exists(NET_KEY_FILE) then gatherEntropy() end
    MASTER_KEY = loadKey(KEY_FILE)
    NET_KEY = loadKey(NET_KEY_FILE)
    CARD_KEY = toHex(sha256("CARD-KEY|" .. MASTER_KEY))
end

-- ====================================================
-- 3. BASE DE DONNEES
-- ====================================================
local bankData = { accounts = {}, globalHistory = {} }
local dirty = false

local function markDirty()
    dirty = true
    os.queueEvent("bank_update")
end

local function newAccount(pin, balance, hidden)
    local salt = toHex(randomBytes(8))
    return {
        pinSalt = salt, pinHash = hashPin(pin, salt),
        balance = balance or 0, wallet = 0, history = {},
        fails = 0, lockUntil = 0, hidden = hidden or nil,
    }
end

local function setPin(acc, pin)
    acc.pinSalt = toHex(randomBytes(8))
    acc.pinHash = hashPin(pin, acc.pinSalt)
    acc.fails, acc.lockUntil = 0, 0
end

-- Ecriture atomique + sauvegarde .bak : un crash ne corrompt jamais la base
local function atomicWrite(path, content)
    local tmp = path .. ".tmp"
    local f = fs.open(tmp, "w")
    if not f then return false end
    f.write(content); f.close()
    if fs.exists(path) then
        if fs.exists(path .. ".bak") then fs.delete(path .. ".bak") end
        fs.move(path, path .. ".bak")
    end
    fs.move(tmp, path)
    return true
end

local function saveNow()
    if atomicWrite(DB_FILE, encrypt(textutils.serialize(bankData), MASTER_KEY)) then
        dirty = false
        return true
    end
    return false
end

local function readEncrypted(path)
    if not fs.exists(path) then return nil, "absent" end
    local f = fs.open(path, "r")
    if not f then return nil, "lecture impossible" end
    local content = (f.readAll() or ""):gsub("%s", "")
    f.close()
    local plain = decrypt(content, MASTER_KEY)
    if not plain then return nil, "dechiffrement/authentification echoue" end
    local data = textutils.unserialize(plain)
    if type(data) ~= "table" or type(data.accounts) ~= "table" then return nil, "format invalide" end
    return data
end

-- Migration depuis l'ancienne base XOR (comptes + soldes + PIN ; les cartes sont a re-lier)
local function legacyCipher(text, key)
    local out, kl = {}, #key
    for i = 1, #text do
        local kb = key:byte(((i - 1) % kl) + 1)
        out[i] = string.char(bxor(text:byte(i), kb + (i % 256)) % 256)
    end
    return table.concat(out)
end

local function migrateLegacy()
    local f = fs.open(LEGACY_DB, "r")
    if not f then return end
    local raw = f.readAll(); f.close()
    local old = textutils.unserialize(legacyCipher(raw, LEGACY_KEY))
    if type(old) ~= "table" or type(old.accounts) ~= "table" then return end
    for name, a in pairs(old.accounts) do
        if name ~= "Admin" and type(a) == "table" then
            local acc = newAccount(tostring(a.pin or "0000"), tonumber(a.balance) or 0)
            for _, h in ipairs(a.history or {}) do
                acc.history[#acc.history + 1] = { k = "info", s = tostring(h) }
            end
            bankData.accounts[name] = acc
        end
    end
    print("Ancienne base migree. Les cartes doivent etre re-liees, changez les PIN.")
end

local function loadData()
    if fs.exists(DB_FILE) or fs.exists(DB_FILE .. ".bak") then
        local data, err = readEncrypted(DB_FILE)
        if not data then
            local bak, err2 = readEncrypted(DB_FILE .. ".bak")
            if not bak then
                error("Base illisible (" .. tostring(err) .. " / " .. tostring(err2)
                    .. "). Arret pour ne pas ecraser vos donnees.", 0)
            end
            data = bak
        end
        bankData = data
    elseif fs.exists(LEGACY_DB) then
        migrateLegacy()
    end
    bankData.globalHistory = bankData.globalHistory or {}
    for _, a in pairs(bankData.accounts) do
        a.history = a.history or {}
        a.wallet = a.wallet or 0
        a.fails = a.fails or 0
        a.lockUntil = a.lockUntil or 0
    end
end

-- Compte admin cache : genere avec un PIN aleatoire affiche UNE seule fois
local function ensureAdmin(force)
    local existing = bankData.accounts[ADMIN_NAME]
    if existing and not force then return end
    local n = 0
    for _, b in ipairs({ randomBytes(4):byte(1, 4) }) do n = n * 256 + b end
    local pin = string.format("%08d", n % 100000000)
    if existing then
        setPin(existing, pin)
    else
        bankData.accounts[ADMIN_NAME] = newAccount(pin, ADMIN_BALANCE, true)
    end
    saveNow()
    term.clear(); term.setCursorPos(1, 1)
    print("=== COMPTE ADMIN CACHE ===")
    print("ID  : " .. ADMIN_NAME)
    print("PIN : " .. pin)
    print("")
    print("Notez-le : il ne sera plus jamais affiche.")
    print("(perdu ? lancez : bankos resetadmin)")
    print("Appuyez sur une touche...")
    os.pullEvent("key")
end

-- ====================================================
-- 4. COMPTES, PIN, HISTORIQUE
-- ====================================================
local function findAccount(name, allowHidden)
    if type(name) ~= "string" then return nil end
    local lname = name:lower()
    for k, v in pairs(bankData.accounts) do
        if k:lower() == lname and (allowHidden or not v.hidden) then return k end
    end
    return nil
end

local function findAccountByCard(id)
    if type(id) ~= "string" then return nil end
    local h = hashCardId(id)
    for name, a in pairs(bankData.accounts) do
        if a.cardHash and safeEqual(a.cardHash, h) then return name end
    end
    return nil
end

-- Verification du PIN avec verrouillage progressif. Retourne ok, raison, secondes
local function checkPin(acc, pin)
    local now = os.epoch("utc")
    if (acc.lockUntil or 0) > now then
        return false, "locked", math.ceil((acc.lockUntil - now) / 1000)
    end
    if type(pin) == "string" and safeEqual(hashPin(pin, acc.pinSalt), acc.pinHash) then
        if (acc.fails or 0) ~= 0 then acc.fails = 0; markDirty() end
        return true
    end
    acc.fails = (acc.fails or 0) + 1
    if acc.fails >= LOCK_AFTER then
        acc.lockUntil = now + math.min(LOCK_BASE_MS * 2 ^ (acc.fails - LOCK_AFTER), 3600000)
    end
    markDirty()
    return false, "bad"
end

local function shownName(name)
    local a = bankData.accounts[name]
    return (a and a.hidden) and "SYSTEME" or name
end

-- kind : "in" (entree), "out" (sortie), "info"
local function logTransaction(accName, kind, text)
    local ts = os.date("%d/%m %H:%M")
    local acc = bankData.accounts[accName]
    if acc then
        acc.history[#acc.history + 1] = { k = kind, s = "[" .. ts .. "] " .. text }
        while #acc.history > HISTORY_ACCOUNT do table.remove(acc.history, 1) end
    end
    if not (acc and acc.hidden) then   -- le compte cache n'apparait pas dans les logs publics
        local g = bankData.globalHistory
        g[#g + 1] = { k = kind, s = "[" .. ts .. "] " .. accName .. ": " .. text }
        while #g > HISTORY_GLOBAL do table.remove(g, 1) end
    end
    markDirty()
end

-- ====================================================
-- 5. CARTES BANCAIRES (le code de carte n'est jamais stocke en clair cote serveur)
-- ====================================================
-- Retourne : statut ("ok" | "blank" | "invalid" | nil), carte, lecteur
local function readCard(assignedDrive)
    local seen, sides = {}, {}
    local function add(n) if not seen[n] then seen[n] = true; sides[#sides + 1] = n end end
    if assignedDrive then
        add(assignedDrive)
    else
        for _, n in ipairs(peripheral.getNames()) do
            if peripheral.getType(n) == "drive" then add(n) end
        end
        for _, s in ipairs({ "top", "bottom", "left", "right", "front", "back" }) do add(s) end
    end
    for _, s in ipairs(sides) do
        if disk.isPresent(s) and disk.hasData(s) then
            local mount = disk.getMountPath(s)
            if mount then
                local path = fs.combine(mount, ".bank_card")
                if not fs.exists(path) then return "blank", nil, s end
                local f = fs.open(path, "r")
                if not f then return "invalid", nil, s end
                local raw = (f.readAll() or ""):gsub("%s", "")
                f.close()
                local plain = decrypt(raw, CARD_KEY)
                local card = plain and textutils.unserialize(plain)
                if type(card) == "table" and type(card.id) == "string" then
                    return "ok", card, s
                end
                return "invalid", nil, s
            end
        end
    end
    return nil
end

local function writeCard(side, id, wallet)
    local mount = disk.getMountPath(side)
    if not mount then return false end
    local f = fs.open(fs.combine(mount, ".bank_card"), "w")
    if not f then return false end
    f.write(encrypt(textutils.serialize({ id = id, wallet = wallet }), CARD_KEY))
    f.close()
    pcall(disk.setLabel, side, "Carte Bancaire")
    return true
end

-- ====================================================
-- 6. MOTEUR D'INTERFACE
-- ====================================================
local function createContext(target_term, target_name, drive_name)
    local ctx = {
        t = target_term, name = target_name, drive = drive_name, buttons = {},
        isColor = target_term.isColor(),
        session = false, timedOut = false, lastAct = os.epoch("utc"),
    }
    ctx.w, ctx.h = ctx.t.getSize()
    return ctx
end

local function clearButtons(ctx) ctx.buttons = {} end

local function addButton(ctx, id, label, x, y, bw, bh, bg, fg, callback)
    ctx.buttons[#ctx.buttons + 1] = { id = id, label = label, x = x, y = y, w = bw, h = bh, bg = bg, fg = fg, cb = callback }
end

local function bc(ctx, c) return ctx.isColor and c or colors.white end
local function ret(v) return function() return v end end

local function drawButtons(ctx)
    for _, b in ipairs(ctx.buttons) do
        for row = 0, b.h - 1 do
            ctx.t.setCursorPos(b.x, b.y + row)
            ctx.t.setBackgroundColor(b.bg)
            ctx.t.setTextColor(b.fg)
            if row == math.floor(b.h / 2) then
                local lbl = string.sub(b.label, 1, b.w)
                local padL = math.floor((b.w - #lbl) / 2)
                ctx.t.write(string.rep(" ", padL) .. lbl .. string.rep(" ", b.w - #lbl - padL))
            else
                ctx.t.write(string.rep(" ", b.w))
            end
        end
    end
end

local function handleTouch(ctx, mx, my)
    for _, b in ipairs(ctx.buttons) do
        if mx >= b.x and mx <= b.x + b.w - 1 and my >= b.y and my <= b.y + b.h - 1 then return b.cb end
    end
    return nil
end

-- Evenements : tick, update, disk_change, touch, timeout, key, char
local function pullCtxEvent(ctx)
    while true do
        local ev = { os.pullEvent() }
        local name = ev[1]
        if name == "bank_tick" then
            if ctx.session and (os.epoch("utc") - ctx.lastAct) > IDLE_TIMEOUT_MS then
                ctx.timedOut = true
                return "timeout"
            end
            return "tick"
        elseif name == "bank_update" then
            return "update"
        elseif name == "disk" or name == "disk_eject" then
            return "disk_change"
        elseif name == "mouse_click" and ctx.name == "computer" then
            ctx.lastAct = os.epoch("utc"); mixEntropy(ev[3] .. "," .. ev[4])
            return "touch", ev[3], ev[4]
        elseif name == "monitor_touch" and ctx.name == ev[2] then
            ctx.lastAct = os.epoch("utc"); mixEntropy(ev[3] .. "," .. ev[4])
            return "touch", ev[3], ev[4]
        elseif (name == "key" or name == "char") and ctx.name == "computer" then
            ctx.lastAct = os.epoch("utc")
            return table.unpack(ev)
        end
    end
end

local function clr(ctx)
    ctx.t.setBackgroundColor(ctx.isColor and colors.gray or colors.black)
    ctx.t.setTextColor(colors.white)
    ctx.t.clear()
end

-- Ecrit du texte tronque a la largeur de l'ecran
local function put(ctx, x, y, text, fg, bg)
    local t = ctx.t
    if bg then t.setBackgroundColor(ctx.isColor and bg or colors.black) end
    t.setTextColor(ctx.isColor and (fg or colors.white) or colors.white)
    t.setCursorPos(x, y)
    t.write(string.sub(text, 1, math.max(0, ctx.w - x + 1)))
end

local function drawHeader(ctx, title)
    local t = ctx.t
    t.setCursorPos(1, 1)
    t.setBackgroundColor(ctx.isColor and colors.blue or colors.gray)
    t.setTextColor(colors.white)
    t.clearLine()
    local clock = textutils.formatTime(os.time(), true)
    local maxT = ctx.w - #clock - 2
    if maxT > 0 then t.write(" " .. string.sub(title, 1, maxT)) end
    t.setCursorPos(ctx.w - #clock + 1, 1)
    t.write(clock)
end

local function drawFooter(ctx, info)
    local t = ctx.t
    t.setCursorPos(1, ctx.h)
    t.setBackgroundColor(ctx.isColor and colors.blue or colors.gray)
    t.setTextColor(colors.white)
    t.clearLine()
    t.write(string.sub(" " .. (info or ""), 1, ctx.w))
end

local function flash(ctx, title, text, color)
    clr(ctx); drawHeader(ctx, title)
    put(ctx, 2, 3, text, color or colors.red)
    sleep(1.5)
end

local function confirmDialog(ctx, title, lines)
    clr(ctx); clearButtons(ctx); drawHeader(ctx, title)
    for i, l in ipairs(lines) do put(ctx, 2, 2 + i, l, colors.white) end
    local by = math.min(ctx.h - 3, 4 + #lines)
    local half = math.floor((ctx.w - 4) / 2)
    addButton(ctx, "no", "Annuler", 2, by, half, 2, bc(ctx, colors.red), colors.black, ret(false))
    addButton(ctx, "yes", "Confirmer", 3 + half, by, half, 2, bc(ctx, colors.green), colors.black, ret(true))
    drawButtons(ctx); drawFooter(ctx, "Confirmez l'operation")
    while true do
        local ev, p1, p2 = pullCtxEvent(ctx)
        if ev == "timeout" then return false
        elseif ev == "tick" then drawHeader(ctx, title)
        elseif ev == "touch" then
            local cb = handleTouch(ctx, p1, p2)
            if cb then return cb() end
        elseif ev == "key" and p1 == keys.enter then return true
        end
    end
end

-- ====================================================
-- 7. CLAVIERS ET SAISIES
-- ====================================================
local function drawInputField(ctx, shown, errorMsg)
    put(ctx, 2, 3, string.sub(" " .. shown .. string.rep(" ", ctx.w), 1, ctx.w - 2), colors.yellow, colors.black)
    put(ctx, 2, 4, string.sub(errorMsg .. string.rep(" ", ctx.w), 1, ctx.w - 2), colors.red,
        ctx.isColor and colors.gray or colors.black)
end

local function getAzertyInput(ctx, title, allowCancel)
    local value, errorMsg = "", ""
    local kb = {
        { "1", "2", "3", "4", "5", "6", "7", "8", "9", "0" },
        { "A", "Z", "E", "R", "T", "Y", "U", "I", "O", "P" },
        { "Q", "S", "D", "F", "G", "H", "J", "K", "L", "M" },
        { "W", "X", "C", "V", "B", "N", "-", "_" },
    }
    clr(ctx); clearButtons(ctx)
    local bH = 1
    local gapY = (ctx.h < 18) and 0 or 1
    local startY = 5

    for r, row in ipairs(kb) do
        local startX = math.max(1, math.floor((ctx.w - #row) / 2) + 1)
        for c, keyText in ipairs(row) do
            addButton(ctx, "k" .. keyText, keyText, startX + c - 1, startY + (r - 1) * (bH + gapY), 1, bH,
                bc(ctx, colors.cyan), colors.black, ret(keyText))
        end
    end
    local lastY = startY + #kb * (bH + gapY)
    addButton(ctx, "DEL", "DEL", 2, lastY, 4, bH, bc(ctx, colors.orange), colors.black, ret("DEL"))
    addButton(ctx, "SPC", "ESP", 7, lastY, ctx.w - 12, bH, bc(ctx, colors.lightGray), colors.black, ret(" "))
    addButton(ctx, "OK", "OK", ctx.w - 4, lastY, 4, bH, bc(ctx, colors.green), colors.black, ret("OK"))
    if allowCancel then
        addButton(ctx, "cancel", "Annuler", 2, math.min(ctx.h - 1, lastY + bH + gapY), ctx.w - 3, 1,
            bc(ctx, colors.red), colors.black, ret("CANCEL"))
    end
    drawButtons(ctx); drawFooter(ctx, "Saisir Identifiant")
    drawHeader(ctx, title); drawInputField(ctx, value, errorMsg)

    while true do
        local ev, p1, p2 = pullCtxEvent(ctx)
        local pressed = nil
        if ev == "timeout" then return nil
        elseif ev == "tick" then drawHeader(ctx, title)
        elseif ev == "touch" then
            local cb = handleTouch(ctx, p1, p2)
            if cb then pressed = cb() end
        elseif ev == "char" and string.match(p1, "^[a-zA-Z0-9%-_ ]$") then pressed = string.upper(p1)
        elseif ev == "key" then
            if p1 == keys.backspace then pressed = "DEL" elseif p1 == keys.enter then pressed = "OK" end
        end

        if pressed then
            if pressed == "DEL" then
                value = string.sub(value, 1, math.max(0, #value - 1)); errorMsg = ""
            elseif pressed == "OK" then
                if #value > 0 then return value end
                errorMsg = "Entrez un nom!"
            elseif pressed == "CANCEL" then return nil
            elseif #value < 12 then value = value .. pressed; errorMsg = "" end
            drawInputField(ctx, value, errorMsg)
        end
    end
end

local function getNumpadInput(ctx, title, isMasked, allowCancel)
    local value, errorMsg = "", ""
    clr(ctx); clearButtons(ctx)
    local btnW = math.floor((ctx.w - 4) / 3)
    local bH, gapY, startY = (ctx.h < 18) and 1 or 2, (ctx.h < 18) and 0 or 1, 5
    local padKeys = { { "1", "2", "3" }, { "4", "5", "6" }, { "7", "8", "9" }, { "DEL", "0", "OK" } }

    for r, row in ipairs(padKeys) do
        for c, keyText in ipairs(row) do
            local bg = colors.cyan
            if keyText == "DEL" then bg = colors.orange elseif keyText == "OK" then bg = colors.green end
            addButton(ctx, "k" .. keyText, keyText, 2 + (c - 1) * (btnW + 1), startY + (r - 1) * (bH + gapY),
                btnW, bH, bc(ctx, bg), colors.black, ret(keyText))
        end
    end
    if allowCancel then
        local cancelY = startY + 4 * (bH + gapY)
        if cancelY < ctx.h then
            addButton(ctx, "cancel", "Annuler", 2, cancelY, ctx.w - 3, 1, bc(ctx, colors.red), colors.black, ret("CANCEL"))
        end
    end
    drawButtons(ctx); drawFooter(ctx, "Saisir Code / Montant")
    drawHeader(ctx, title)
    drawInputField(ctx, value, errorMsg)

    while true do
        local ev, p1, p2 = pullCtxEvent(ctx)
        local pressed = nil
        if ev == "timeout" then return nil
        elseif ev == "tick" then drawHeader(ctx, title)
        elseif ev == "touch" then
            local cb = handleTouch(ctx, p1, p2)
            if cb then pressed = cb() end
        elseif ev == "char" and string.match(p1, "^[0-9]$") then pressed = p1
        elseif ev == "key" then
            if p1 == keys.backspace then pressed = "DEL"
            elseif p1 == keys.enter or p1 == keys.numPadEnter then pressed = "OK"
            elseif p1 == keys.delete and allowCancel then pressed = "CANCEL" end
        end

        if pressed then
            if pressed == "DEL" then
                value = string.sub(value, 1, math.max(0, #value - 1)); errorMsg = ""
            elseif pressed == "OK" then
                if #value > 0 then return value end
                errorMsg = "Valeur vide!"
            elseif pressed == "CANCEL" then return nil
            elseif #value < 8 then value = value .. pressed; errorMsg = "" end
            drawInputField(ctx, isMasked and string.rep("*", #value) or value, errorMsg)
        end
    end
end

-- ====================================================
-- 8. DASHBOARD (session ouverte)
-- ====================================================
local function drawWidget(ctx, session)
    local a = bankData.accounts[session.name]
    if not a then return end
    local t = ctx.t
    t.setBackgroundColor(colors.black)
    for y = 3, 7 do
        t.setCursorPos(2, y); t.write(string.rep(" ", ctx.w - 2))
    end
    put(ctx, 3, 3, "TITULAIRE : ", colors.lightBlue, colors.black)
    put(ctx, 15, 3, session.name, colors.white)
    put(ctx, 3, 4, string.rep("-", ctx.w - 4), colors.gray)
    put(ctx, 3, 5, "COMPTE : $ " .. fmt(a.balance), colors.lime)
    put(ctx, 3, 6, "CARTE  : $ " .. fmt(a.wallet), colors.yellow)
    if a.loan then
        put(ctx, 3, 7, "DETTE  : $ " .. fmt(a.loan.owed), colors.red)
    else
        put(ctx, 3, 7, "Aucune dette", colors.gray)
    end
end

local function runDashboard(ctx, session)
    ctx.session = true; ctx.timedOut = false; ctx.lastAct = os.epoch("utc")
    local function acc() return bankData.accounts[session.name] end

    -- carte inseree appartenant bien a ce compte
    local function ownCard()
        local status, card, side = readCard(ctx.drive)
        if status == "ok" and findAccountByCard(card.id) == session.name then return side, card end
        return nil
    end

    local function askAmount(title)
        local n = tonumber(getNumpadInput(ctx, title, false, true))
        if n and n >= 1 then return n end
        return nil
    end

    local function doWithdraw()
        local side, card = ownCard()
        if not side then return flash(ctx, "Retrait", "Inserez VOTRE carte", colors.red) end
        local amt = askAmount("Montant Retrait")
        if not amt then return end
        local a = acc()
        if a.balance < amt then return flash(ctx, "Erreur", "Fonds insuffisants", colors.red) end
        a.balance = a.balance - amt
        a.wallet = a.wallet + amt
        if writeCard(side, card.id, a.wallet) then
            logTransaction(session.name, "out", "-$" .. fmt(amt) .. " (Retrait sur carte)")
            flash(ctx, "Succes", "Argent sur la carte !", colors.lime)
        else
            a.balance = a.balance + amt
            a.wallet = a.wallet - amt
            flash(ctx, "Erreur", "Ecriture carte echouee", colors.red)
        end
    end

    local function doDeposit()
        local side, card = ownCard()
        if not side then return flash(ctx, "Depot", "Inserez VOTRE carte", colors.red) end
        if acc().wallet < 1 then return flash(ctx, "Depot", "Carte vide", colors.red) end
        local amt = askAmount("Montant Depot")
        if not amt then return end
        local a = acc()
        if a.wallet < amt then return flash(ctx, "Erreur", "Pas assez sur la carte", colors.red) end
        a.wallet = a.wallet - amt
        a.balance = a.balance + amt
        if writeCard(side, card.id, a.wallet) then
            logTransaction(session.name, "in", "+$" .. fmt(amt) .. " (Depot depuis carte)")
            flash(ctx, "Succes", "Depot effectue !", colors.lime)
        else
            a.wallet = a.wallet + amt
            a.balance = a.balance - amt
            flash(ctx, "Erreur", "Ecriture carte echouee", colors.red)
        end
    end

    local function doTransfer()
        local input = getAzertyInput(ctx, "Destinataire", true)
        if not input then return end
        local target = findAccount(input, false)
        if not target then return flash(ctx, "Erreur", "Compte introuvable", colors.red) end
        if target == session.name then return flash(ctx, "Erreur", "Transfert impossible", colors.red) end
        local amt = askAmount("Montant Virement")
        if not amt then return end
        local a = acc()
        if a.balance < amt then return flash(ctx, "Erreur", "Fonds insuffisants", colors.red) end
        a.balance = a.balance - amt
        bankData.accounts[target].balance = bankData.accounts[target].balance + amt
        logTransaction(session.name, "out", "-$" .. fmt(amt) .. " -> " .. target)
        logTransaction(target, "in", "+$" .. fmt(amt) .. " <- " .. shownName(session.name))
        flash(ctx, "Succes", "Virement effectue !", colors.lime)
    end

    local function doLoan()
        local a = acc()
        if a.loan then
            return flash(ctx, "Emprunt", "Dette en cours: $" .. fmt(a.loan.owed), colors.red)
        end
        local amt = askAmount("Montant Emprunt")
        if not amt then return end
        if amt > LOAN_MAX then return flash(ctx, "Emprunt", "Maximum $" .. fmt(LOAN_MAX), colors.red) end
        local rate = loanRate(amt)
        local interest = math.max(1, math.floor(amt * rate + 0.5))
        local owed = amt + interest
        local pct = string.format("%.0f%%", rate * 100)
        local yes = confirmDialog(ctx, "Emprunt", {
            "Emprunt  : $" .. fmt(amt),
            "Taux     : " .. pct,
            "Interets : $" .. fmt(interest),
            "A rendre : $" .. fmt(owed),
        })
        if not yes then return end
        a = acc()
        if a.loan then return end
        a.balance = a.balance + amt
        a.loan = { principal = amt, owed = owed, rate = rate, ts = os.epoch("utc") }
        logTransaction(session.name, "in", "+$" .. fmt(amt) .. " (Emprunt " .. pct .. ")")
        flash(ctx, "Succes", "Emprunt accorde !", colors.lime)
    end

    local function doRepay()
        local a = acc()
        if not a.loan then return flash(ctx, "Remboursement", "Aucune dette", colors.red) end
        local amt = askAmount("Rembourser")
        if not amt then return end
        a = acc()
        if not a.loan then return end
        amt = math.min(amt, a.loan.owed)
        if a.balance < amt then return flash(ctx, "Erreur", "Fonds insuffisants", colors.red) end
        a.balance = a.balance - amt
        a.loan.owed = a.loan.owed - amt
        logTransaction(session.name, "out", "-$" .. fmt(amt) .. " (Remboursement)")
        if a.loan.owed <= 0 then
            a.loan = nil
            markDirty()
            flash(ctx, "Succes", "Dette soldee !", colors.lime)
        else
            flash(ctx, "Succes", "Reste $" .. fmt(a.loan.owed), colors.lime)
        end
    end

    local function doLinkCard()
        local status, card, side = readCard(ctx.drive)
        if not side then return flash(ctx, "Erreur", "Inserez disquette", colors.red) end
        if status == "ok" then
            local owner = findAccountByCard(card.id)
            if owner and owner ~= session.name then
                return flash(ctx, "Erreur", "Carte d'un autre compte", colors.red)
            end
        end
        local id = toHex(randomBytes(16))
        if writeCard(side, id, acc().wallet) then
            acc().cardHash = hashCardId(id)
            logTransaction(session.name, "info", "Carte liee")
            flash(ctx, "Succes", "Carte liee !", colors.lime)
        else
            flash(ctx, "Erreur", "Erreur d'ecriture", colors.red)
        end
    end

    local function doChangePin()
        local a = acc()
        local old = getNumpadInput(ctx, "PIN actuel", true, true)
        if not old then return end
        local ok, why, wait = checkPin(a, old)
        if not ok then
            return flash(ctx, "Erreur", why == "locked" and ("Verrouille " .. wait .. "s") or "PIN incorrect", colors.red)
        end
        local p1 = getNumpadInput(ctx, "Nouveau PIN", true, true)
        if not p1 then return end
        if #p1 < PIN_MIN_LEN then
            return flash(ctx, "Erreur", "PIN : " .. PIN_MIN_LEN .. " chiffres min", colors.red)
        end
        local p2 = getNumpadInput(ctx, "Confirmer PIN", true, true)
        if p2 ~= p1 then return flash(ctx, "Erreur", "PIN differents", colors.red) end
        setPin(a, p1)
        logTransaction(session.name, "info", "PIN modifie")
        flash(ctx, "Succes", "PIN mis a jour !", colors.lime)
    end

    local function showHistory()
        clr(ctx); clearButtons(ctx); drawHeader(ctx, "Mes Transactions")
        addButton(ctx, "back", "Retour", 2, ctx.h - 1, ctx.w - 3, 1, bc(ctx, colors.lightBlue), colors.black, ret("back"))
        drawButtons(ctx)
        local list = acc().history
        local y = 3
        for i = #list, 1, -1 do
            if y >= ctx.h - 1 then break end
            local e = list[i]
            put(ctx, 2, y, e.s, e.k == "in" and colors.lime or e.k == "out" and colors.orange or colors.white,
                ctx.isColor and colors.gray or colors.black)
            y = y + 1
        end
        while true do
            local ev, p1, p2 = pullCtxEvent(ctx)
            if ev == "timeout" then return end
            if ev == "touch" and handleTouch(ctx, p1, p2) then return end
        end
    end

    local function snap(a)
        return tostring(a.balance) .. ":" .. tostring(a.wallet) .. ":" .. tostring(a.loan and a.loan.owed or 0)
    end

    local actions = {
        depot = doDeposit, retrait = doWithdraw, transfert = doTransfer, emprunt = doLoan,
        rembourser = doRepay, card = doLinkCard, change_pin = doChangePin, history = showHistory,
    }

    while not ctx.timedOut do
        local a = acc()
        if not a then break end
        if session.viaCard and not ownCard() then break end   -- carte retiree = deconnexion

        clr(ctx); clearButtons(ctx)
        drawWidget(ctx, session)

        local top = 9
        local count = ctx.h - 1 - top
        local bH, gap
        if 4 * 2 + 3 <= count then bH, gap = 2, 1
        elseif 4 + 3 <= count then bH, gap = 1, 1
        else bH, gap = 1, 0 end
        local colW = math.floor((ctx.w - 5) / 2)
        local c1, c2 = 2, 2 + colW + 1
        local function rowY(i) return top + (i - 1) * (bH + gap) end

        addButton(ctx, "dep", "Depot", c1, rowY(1), colW, bH, bc(ctx, colors.green), colors.black, ret("depot"))
        addButton(ctx, "tra", "Transfert", c1, rowY(2), colW, bH, bc(ctx, colors.purple), colors.black, ret("transfert"))
        addButton(ctx, "emp", "Emprunt", c1, rowY(3), colW, bH, bc(ctx, colors.magenta), colors.black, ret("emprunt"))
        addButton(ctx, "his", "Historique", c1, rowY(4), colW, bH, bc(ctx, colors.lightBlue), colors.black, ret("history"))
        addButton(ctx, "ret", "Retrait", c2, rowY(1), colW, bH, bc(ctx, colors.orange), colors.black, ret("retrait"))
        addButton(ctx, "rem", "Rembourser", c2, rowY(2), colW, bH, bc(ctx, colors.pink), colors.black, ret("rembourser"))
        addButton(ctx, "crd", "Lier Carte", c2, rowY(3), colW, bH, bc(ctx, colors.yellow), colors.black, ret("card"))
        addButton(ctx, "pin", "Modif. PIN", c2, rowY(4), colW, bH, bc(ctx, colors.cyan), colors.black, ret("change_pin"))
        addButton(ctx, "quit", "Deconnexion", 2, ctx.h - 1, ctx.w - 3, 1, bc(ctx, colors.red), colors.black, ret("logout"))

        drawButtons(ctx); drawFooter(ctx, "Session : " .. session.name)
        drawHeader(ctx, "BankOS - Dashboard")

        local last = snap(a)
        local action = nil
        while not action and not ctx.timedOut do
            local ev, p1, p2 = pullCtxEvent(ctx)
            if ev == "timeout" or ev == "disk_change" then
                break
            elseif ev == "tick" or ev == "update" then
                drawHeader(ctx, "BankOS - Dashboard")
                local cur = acc()
                if cur and snap(cur) ~= last then
                    last = snap(cur)
                    drawWidget(ctx, session)
                end
            elseif ev == "touch" then
                local cb = handleTouch(ctx, p1, p2)
                if cb then action = cb() end
            end
        end

        if action == "logout" then break end
        if action and actions[action] then actions[action]() end
    end
    ctx.session = false
end

-- ====================================================
-- 9. TERMINAL PRINCIPAL (ATM)
-- ====================================================
local function runAtmTerminal(target_term, target_name, drive_name)
    local ctx = createContext(target_term, target_name, drive_name)
    local ignoredCard = nil   -- carte ignoree jusqu'a son retrait (deconnexion / annulation)

    local function tryCardLogin(card)
        local accName = findAccountByCard(card.id)
        if not accName then
            flash(ctx, "Erreur", "Carte non reconnue", colors.red)
            ignoredCard = card.id
            return nil
        end
        local pin = getNumpadInput(ctx, "PIN " .. accName, true, true)
        if not pin then ignoredCard = card.id; return nil end
        local ok, why, wait = checkPin(bankData.accounts[accName], pin)
        if ok then return { name = accName, viaCard = true } end
        if why == "locked" then
            ignoredCard = card.id
            flash(ctx, "Verrouille", "Reessayez dans " .. wait .. "s", colors.red)
        else
            flash(ctx, "Erreur", "PIN incorrect", colors.red)
            -- compte verrouille par cet essai : on n'insiste plus tant que la carte n'est pas retiree
            if (bankData.accounts[accName].lockUntil or 0) > os.epoch("utc") then ignoredCard = card.id end
        end
        return nil
    end

    local function loginById()
        local nameInput = getAzertyInput(ctx, "ID Compte", true)
        if not nameInput then return nil end
        local real = findAccount(nameInput, true)
        local pin = getNumpadInput(ctx, "Code PIN", true, true)
        if not pin then return nil end
        if not real then
            hashPin(pin, "0000000000000000")   -- meme duree que pour un vrai compte
            flash(ctx, "Erreur", "Identifiants invalides", colors.red)
            return nil
        end
        local acc = bankData.accounts[real]
        local ok, why, wait = checkPin(acc, pin)
        if ok then return { name = real, viaCard = false } end
        if why == "locked" and not acc.hidden then
            flash(ctx, "Verrouille", "Reessayez dans " .. wait .. "s", colors.red)
        else
            flash(ctx, "Erreur", "Identifiants invalides", colors.red)
        end
        return nil
    end

    local function register()
        local nameInput = getAzertyInput(ctx, "Nouveau Nom", true)
        if not nameInput then return nil end
        if #nameInput < 3 or not nameInput:match("^[%w_%-]+$") or nameInput:upper() == "SYSTEME"
            or findAccount(nameInput, true) then
            flash(ctx, "Erreur", "Nom indisponible", colors.red)
            return nil
        end
        local p1 = getNumpadInput(ctx, "Nouveau PIN", true, true)
        if not p1 then return nil end
        if #p1 < PIN_MIN_LEN then
            flash(ctx, "Erreur", "PIN : " .. PIN_MIN_LEN .. " chiffres min", colors.red)
            return nil
        end
        local p2 = getNumpadInput(ctx, "Confirmer PIN", true, true)
        if p2 ~= p1 then
            flash(ctx, "Erreur", "PIN differents", colors.red)
            return nil
        end
        bankData.accounts[nameInput] = newAccount(p1, 0)
        logTransaction("SYSTEME", "info", "Creation compte: " .. nameInput)
        flash(ctx, "Succes", "Compte cree !", colors.lime)
        return { name = nameInput, viaCard = false }
    end

    while true do
        local session = nil

        while not session do
            local status, card = readCard(ctx.drive)
            if not (status == "ok" and card.id == ignoredCard) then ignoredCard = nil end

            if status == "ok" and card.id ~= ignoredCard then
                session = tryCardLogin(card)
            else
                clr(ctx); clearButtons(ctx)
                drawHeader(ctx, "BankOS - Accueil")
                put(ctx, 2, 3, "=== DISTRIBUTEUR ATM ===", colors.cyan, colors.black)
                local msg = "Inserez votre carte bancaire"
                if ignoredCard then msg = "Retirez votre carte"
                elseif status == "blank" then msg = "Carte vierge : connectez-vous"
                elseif status == "invalid" then msg = "Carte illisible" end
                drawFooter(ctx, msg)
                local btnW = ctx.w - 4
                addButton(ctx, "btn_log", "Se Connecter", 2, 6, btnW, 2, bc(ctx, colors.green), colors.black, ret("login"))
                addButton(ctx, "btn_reg", "S'inscrire", 2, 9, btnW, 2, bc(ctx, colors.cyan), colors.black, ret("register"))
                drawButtons(ctx)

                local action = nil
                while not action do
                    local ev, p1, p2 = pullCtxEvent(ctx)
                    if ev == "tick" then drawHeader(ctx, "BankOS - Accueil")
                    elseif ev == "disk_change" then break
                    elseif ev == "touch" then
                        local cb = handleTouch(ctx, p1, p2)
                        if cb then action = cb() end
                    end
                end

                if action == "login" then session = loginById()
                elseif action == "register" then session = register() end
            end
        end

        runDashboard(ctx, session)

        -- Apres deconnexion, une carte encore inseree est ignoree jusqu'a son retrait
        local status, card = readCard(ctx.drive)
        if status == "ok" then ignoredCard = card.id end
    end
end

-- ====================================================
-- 10. SERVEUR : LOGS + API REDNET (chiffree, anti-rejeu)
-- ====================================================
local SERVER_START = os.epoch("utc")
local seenNonces, rateLimit = {}, {}

local function apiReply(senderId, nonce, ok, message, extra)
    local resp = { ok = ok, message = message, nonce = nonce, ts = os.epoch("utc") }
    if extra then for k, v in pairs(extra) do resp[k] = v end end
    rednet.send(senderId, encrypt(textutils.serialize(resp), NET_KEY), PROTOCOL)
end

local function pruneApiState(now)
    for n, exp in pairs(seenNonces) do if exp < now then seenNonces[n] = nil end end
    for id, r in pairs(rateLimit) do if now - r.t0 > 10000 then rateLimit[id] = nil end end
end

local function handleApi(senderId, msg)
    if type(msg) ~= "string" or #msg > 4096 then return end
    local now = os.epoch("utc")
    pruneApiState(now)

    -- 1. limite de debit AVANT tout calcul (20 requetes / 10 s / emetteur)
    local r = rateLimit[senderId]
    if not r then r = { t0 = now, n = 0 }; rateLimit[senderId] = r end
    r.n = r.n + 1
    if r.n > 20 then return end

    -- 2. authenticite : sans la cle reseau, aucune reponse
    local plain = decrypt(msg, NET_KEY)
    if not plain then return end
    local req = textutils.unserialize(plain)
    if type(req) ~= "table" then return end
    local nonce = req.nonce
    if type(nonce) ~= "string" or #nonce < 16 or #nonce > 64 then return end

    -- 3. anti-rejeu : horodatage recent, posterieur au demarrage, nonce jamais vu
    if type(req.ts) ~= "number" or req.ts < SERVER_START or math.abs(now - req.ts) > API_WINDOW_MS then
        return apiReply(senderId, nonce, false, "Requete expiree")
    end
    if seenNonces[nonce] then return end
    seenNonces[nonce] = now + 2 * API_WINDOW_MS

    -- 4. validation stricte des champs
    if req.type ~= "PAYMENT" then return apiReply(senderId, nonce, false, "Type inconnu") end
    local amount = req.amount
    if type(req.account) ~= "string" or type(req.pin) ~= "string" or type(req.target) ~= "string"
        or #req.account > 32 or #req.pin > 12 or #req.target > 32
        or type(amount) ~= "number" or amount ~= math.floor(amount)
        or amount < 1 or amount > API_MAX_AMOUNT then
        return apiReply(senderId, nonce, false, "Requete invalide")
    end

    local accName = findAccount(req.account, false)
    if not accName then return apiReply(senderId, nonce, false, "Identifiants invalides") end
    local acc = bankData.accounts[accName]
    local ok, why = checkPin(acc, req.pin)
    if not ok then
        return apiReply(senderId, nonce, false, why == "locked" and "Compte verrouille" or "Identifiants invalides")
    end

    local target = findAccount(req.target, false)
    if not target then return apiReply(senderId, nonce, false, "Destinataire inconnu") end
    if target == accName then return apiReply(senderId, nonce, false, "Paiement a soi-meme impossible") end

    local source = (req.source == "wallet") and "wallet" or "balance"
    if acc[source] < amount then return apiReply(senderId, nonce, false, "Fonds insuffisants") end

    local memo = ""
    if type(req.memo) == "string" then
        memo = req.memo:gsub("[^%w %.%-_]", "")
        memo = memo:sub(1, 24)
        if #memo > 0 then memo = " [" .. memo .. "]" end
    end

    acc[source] = acc[source] - amount
    bankData.accounts[target].balance = bankData.accounts[target].balance + amount
    logTransaction(accName, "out", "-$" .. fmt(amount) .. " -> " .. target .. memo)
    logTransaction(target, "in", "+$" .. fmt(amount) .. " <- " .. accName .. memo)
    apiReply(senderId, nonce, true, "Paiement valide", { txid = toHex(randomBytes(6)) })
end

local function runServer(showLogs)
    for _, name in ipairs(peripheral.getNames()) do
        if peripheral.getType(name) == "modem" then pcall(rednet.open, name) end
    end

    local function drawLogs()
        local w, h = term.getSize()
        local col = term.isColor()
        term.setBackgroundColor(colors.black); term.clear()
        term.setCursorPos(1, 1)
        term.setBackgroundColor(col and colors.blue or colors.gray)
        term.setTextColor(colors.white); term.clearLine()
        term.write(" LOGS SERVEUR - BankOS v2")
        term.setBackgroundColor(colors.black)
        local y = 3
        local hist = bankData.globalHistory
        for i = #hist, math.max(1, #hist - (h - 4)), -1 do
            term.setCursorPos(2, y)
            local e = hist[i]
            if col then
                term.setTextColor(e.k == "in" and colors.lime or e.k == "out" and colors.red or colors.lightGray)
            else
                term.setTextColor(colors.white)
            end
            term.write(string.sub(e.s, 1, w - 2))
            y = y + 1
        end
    end

    if showLogs then drawLogs() end
    while true do
        local ev, p1, p2, p3 = os.pullEvent()
        if ev == "bank_update" or ev == "term_resize" then
            if showLogs then drawLogs() end
        elseif ev == "rednet_message" and p3 == PROTOCOL then
            pcall(handleApi, p1, p2)   -- une requete malformee ne peut plus faire tomber le serveur
        end
    end
end

-- ====================================================
-- LANCEMENT : 1 ATM (moniteur) + 1 SERVEUR (ecran interne)
-- ====================================================
local args = { ... }

initKeys()
loadData()

if args[1] == "resetadmin" then
    ensureAdmin(true)
    return
end
ensureAdmin(false)

local tasks = {}
tasks[#tasks + 1] = function()
    while true do
        sleep(1)
        if dirty then saveNow() end
        os.queueEvent("bank_tick")
    end
end

local monitor = peripheral.find("monitor")
local drive = peripheral.find("drive")
local driveName = drive and peripheral.getName(drive) or nil

-- Sans moniteur, l'ATM occupe l'ecran de l'ordinateur : pas d'ecran de logs
tasks[#tasks + 1] = function() runServer(monitor ~= nil) end

if monitor then
    local monitorName = peripheral.getName(monitor)
    monitor.setTextScale(0.5)
    tasks[#tasks + 1] = function() runAtmTerminal(monitor, monitorName, driveName) end
else
    tasks[#tasks + 1] = function() runAtmTerminal(term.native(), "computer", driveName) end
end

term.redirect(term.native())
parallel.waitForAll(table.unpack(tasks))
