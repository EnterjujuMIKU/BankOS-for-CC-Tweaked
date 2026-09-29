-- ====================================================
-- BankOS - Système Bancaire Sécurisé (Monobloc + Serveur)
-- ====================================================

local MASTER_KEY = "CraftBank_Secret_Key_2026"
local dataFile = "bank_data.txt"
local historyFile = "globalHistory.txt"

-- ====================================================
-- 1. MODULE DE CHIFFREMENT & HACHAGE
-- ====================================================
local function cipher(text, key)
    local result = {}
    local keyLen = #key
    for i = 1, #text do
        local charCode = string.byte(text, i)
        local keyByte = string.byte(key, ((i - 1) % keyLen) + 1)
        local encryptedByte = bit.bxor(charCode, keyByte + (i % 256)) % 256
        table.insert(result, string.char(encryptedByte))
    end
    return table.concat(result)
end

local function generateCardCode()
    local charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local code = ""
    for i = 1, 24 do
        local rand = math.random(1, #charset)
        code = code .. string.sub(charset, rand, rand)
        if i % 4 == 0 and i < 24 then code = code .. "-" end
    end
    return code
end

local function hashCardCode(rawCode)
    local salt = "CraftBank2026"
    local combined = rawCode .. salt
    local charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    
    local hashBytes = {}
    for i = 1, 24 do hashBytes[i] = string.byte(salt, (i % #salt) + 1) end
    
    for i = 1, #combined do
        local charByte = string.byte(combined, i)
        local pos = ((i - 1) % 24) + 1
        hashBytes[pos] = bit.bxor(hashBytes[pos], charByte * 31 + i) % 256
    end
    
    local finalHash = ""
    for i = 1, 24 do
        local index = (hashBytes[i] % #charset) + 1
        finalHash = finalHash .. string.sub(charset, index, index)
        if i % 4 == 0 and i < 24 then finalHash = finalHash .. "-" end
    end
    
    return finalHash
end

-- ====================================================
-- 2. BASE DE DONNEES & FICHIERS
-- ====================================================
local bankData = {
    accounts = {
        ["Twilight"] = { pin = "1234", balance = 1500, cardHash = nil, history = {} },
        ["Admin"] = { pin = "0000", balance = 9999, cardHash = nil, history = {} }
    }
}

local globalHistory = {}

local function saveGlobalHistory()
    local serialized = textutils.serialize(globalHistory)
    local encrypted = cipher(serialized, MASTER_KEY)
    local f = fs.open(historyFile, "w")
    if f then
        f.write(encrypted)
        f.close()
    end
end

local function loadGlobalHistory()
    if fs.exists(historyFile) then
        local f = fs.open(historyFile, "r")
        if f then
            local encrypted = f.readAll()
            f.close()
            local decrypted = cipher(encrypted, MASTER_KEY)
            local parsed = textutils.unserialize(decrypted)
            if parsed and type(parsed) == "table" then
                globalHistory = parsed
            end
        end
    else
        saveGlobalHistory()
    end
end

local function saveData()
    local serialized = textutils.serialize(bankData)
    local encrypted = cipher(serialized, MASTER_KEY)
    local f = fs.open(dataFile, "w")
    if f then
        f.write(encrypted)
        f.close()
    end
    saveGlobalHistory()
    os.queueEvent("bank_update")
end

local function loadData()
    if fs.exists(dataFile) then
        local f = fs.open(dataFile, "r")
        if f then
            local encrypted = f.readAll()
            f.close()
            local decrypted = cipher(encrypted, MASTER_KEY)
            local parsed = textutils.unserialize(decrypted)
            if parsed and parsed.accounts then 
                bankData = parsed 
                for k, v in pairs(bankData.accounts) do
                    if not v.history then v.history = {} end
                end
            end
        end
    else
        saveData()
    end
    loadGlobalHistory()
end

local function getAccountByName(name)
    for k, v in pairs(bankData.accounts) do
        if string.lower(k) == string.lower(name) then
            return k
        end
    end
    return nil
end

local function getAccountByCard(rawCardId)
    if not rawCardId or rawCardId == "UNLINKED" then return nil end
    local computedHash = hashCardCode(rawCardId)
    for k, v in pairs(bankData.accounts) do
        if v.cardHash == computedHash then
            return k
        end
    end
    return nil
end

local function logTransaction(accountName, actionText)
    local timestamp = textutils.formatTime(os.time(), true)
    local entry = string.format("[%s] %s", timestamp, actionText)
    
    table.insert(globalHistory, string.format("[%s] %s: %s", timestamp, accountName, actionText))
    if #globalHistory > 50 then table.remove(globalHistory, 1) end
    
    if bankData.accounts[accountName] then
        if not bankData.accounts[accountName].history then bankData.accounts[accountName].history = {} end
        table.insert(bankData.accounts[accountName].history, entry)
        if #bankData.accounts[accountName].history > 10 then 
            table.remove(bankData.accounts[accountName].history, 1) 
        end
    end
    
    saveData()
end

-- ====================================================
-- 3. GESTION DES CARTES BANCAIRES
-- ====================================================
local function getInsertedCardId(assignedDrive)
    local drives = {}
    if assignedDrive then
        drives = { assignedDrive }
    else
        for _, name in ipairs(peripheral.getNames()) do
            if peripheral.getType(name) == "drive" then
                table.insert(drives, name)
            end
        end
        for _, side in ipairs({"top", "bottom", "left", "right", "front", "back"}) do
            table.insert(drives, side)
        end
    end
    
    for _, s in ipairs(drives) do
        if peripheral.isPresent(s) or disk.isPresent(s) then
            if disk.isPresent(s) and disk.hasData(s) then
                local mountPath = disk.getMountPath(s)
                if mountPath then
                    local cardFile = fs.combine(mountPath, ".bank_card")
                    if fs.exists(cardFile) then
                        local f = fs.open(cardFile, "r")
                        if f then
                            local rawCardId = cipher(f.readAll(), MASTER_KEY)
                            f.close()
                            return rawCardId, s
                        end
                    else
                        return "UNLINKED", s
                    end
                end
            end
        end
    end
    return nil, nil
end

local function writeCardId(side, rawCardId)
    local mountPath = disk.getMountPath(side)
    if mountPath then
        local cardFile = fs.combine(mountPath, ".bank_card")
        local f = fs.open(cardFile, "w")
        if f then
            f.write(cipher(rawCardId, MASTER_KEY))
            f.close()
            disk.setLabel(side, "Carte Bancaire")
            return true
        end
    end
    return false
end

-- ====================================================
-- 4. MOTEUR D'INTERFACE
-- ====================================================
local function createContext(target_term, target_name, drive_name)
    local ctx = { 
        t = target_term, 
        name = target_name, 
        drive = drive_name, 
        buttons = {}, 
        isColor = target_term.isColor() 
    }
    ctx.w, ctx.h = ctx.t.getSize()
    return ctx
end

local function clearButtons(ctx) ctx.buttons = {} end

local function addButton(ctx, id, label, x, y, bw, bh, bg, fg, callback)
    table.insert(ctx.buttons, {
        id = id, label = label, x = x, y = y, w = bw, h = bh, bg = bg, fg = fg, cb = callback
    })
end

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

local function pullCtxEvent(ctx)
    while true do
        local ev = {os.pullEvent()}
        local type = ev[1]
        
        if type == "bank_tick" then
            return "tick"
        elseif type == "disk" or type == "disk_eject" then
            return "disk_change"
        elseif type == "mouse_click" and ctx.name == "computer" then
            return "touch", ev[3], ev[4]
        elseif type == "monitor_touch" and ctx.name == ev[2] then
            return "touch", ev[3], ev[4]
        elseif (type == "key" or type == "char") and ctx.name == "computer" then
            return table.unpack(ev)
        end
    end
end

local function clr(ctx)
    ctx.t.setBackgroundColor(ctx.isColor and colors.gray or colors.black)
    ctx.t.setTextColor(colors.white)
    ctx.t.clear()
end

local function drawHeader(ctx, title)
    ctx.t.setCursorPos(1, 1)
    ctx.t.setBackgroundColor(ctx.isColor and colors.blue or colors.gray)
    ctx.t.setTextColor(colors.white)
    ctx.t.clearLine()
    local clock = textutils.formatTime(os.time(), true)
    local maxT = ctx.w - #clock - 2
    if maxT > 0 then ctx.t.write(" " .. string.sub(title, 1, maxT)) end
    ctx.t.setCursorPos(ctx.w - #clock + 1, 1)
    ctx.t.write(clock)
end

local function drawFooter(ctx, info)
    ctx.t.setCursorPos(1, ctx.h)
    ctx.t.setBackgroundColor(ctx.isColor and colors.blue or colors.gray)
    ctx.t.setTextColor(colors.white)
    ctx.t.clearLine()
    ctx.t.write(string.sub(" " .. (info or ""), 1, ctx.w))
end

-- ====================================================
-- 5. CLAVIERS ET SAISIES
-- ====================================================
local function getAzertyInput(ctx, title, allowCancel)
    local value, errorMsg = "", ""
    local kb = {
        {"A","Z","E","R","T","Y","U","I","O","P"},
        {"Q","S","D","F","G","H","J","K","L","M"},
        {"W","X","C","V","B","N","-","_"}
    }
    clr(ctx); clearButtons(ctx)

    local bH = 1
    local gapY = (ctx.h < 16) and 0 or 1
    local startY = 5

    for r, row in ipairs(kb) do
        local startX = math.max(1, math.floor((ctx.w - #row) / 2) + 1)
        for c, keyText in ipairs(row) do
            addButton(ctx, "k"..keyText, keyText, startX + c - 1, startY + (r-1)*(bH+gapY), 1, bH, (ctx.isColor and colors.cyan or colors.white), colors.black, function() return keyText end)
        end
    end

    local lastY = startY + 3 * (bH + gapY)
    addButton(ctx, "DEL", "DEL", 2, lastY, 4, bH, (ctx.isColor and colors.orange or colors.white), colors.black, function() return "DEL" end)
    addButton(ctx, "SPC", "ESP", 7, lastY, ctx.w - 12, bH, colors.gray, colors.white, function() return " " end)
    addButton(ctx, "OK", "OK", ctx.w - 4, lastY, 4, bH, (ctx.isColor and colors.green or colors.white), colors.black, function() return "OK" end)
    
    if allowCancel then
        addButton(ctx, "cancel", "Annuler", 2, math.min(ctx.h - 1, lastY + bH + gapY), ctx.w - 3, 1, (ctx.isColor and colors.red or colors.white), colors.white, function() return "CANCEL" end)
    end

    drawButtons(ctx); drawFooter(ctx, "Saisir Identifiant")

    local function drawField()
        ctx.t.setCursorPos(2, 3)
        ctx.t.setBackgroundColor(colors.black); ctx.t.setTextColor(colors.yellow)
        ctx.t.write(string.sub(" " .. value .. string.rep(" ", math.max(0, ctx.w - 2 - #value - 1)), 1, ctx.w - 2))
        ctx.t.setCursorPos(2, 4)
        if errorMsg ~= "" then
            ctx.t.setTextColor(ctx.isColor and colors.red or colors.white); ctx.t.setBackgroundColor(ctx.isColor and colors.gray or colors.black)
            ctx.t.write(string.sub(errorMsg .. string.rep(" ", ctx.w), 1, ctx.w - 2))
        else
            ctx.t.setBackgroundColor(ctx.isColor and colors.gray or colors.black); ctx.t.write(string.rep(" ", ctx.w - 2))
        end
    end

    drawHeader(ctx, title); drawField()

    while true do
        local evType, p1, p2 = pullCtxEvent(ctx)
        local pressedKey = nil
        if evType == "tick" then drawHeader(ctx, title)
        elseif evType == "touch" then local cb = handleTouch(ctx, p1, p2); if cb then pressedKey = cb() end
        elseif evType == "char" and string.match(p1, "[a-zA-Z0-9%-_ ]") then pressedKey = string.upper(p1)
        elseif evType == "key" then
            if p1 == keys.backspace then pressedKey = "DEL" elseif p1 == keys.enter then pressedKey = "OK" end
        end

        if pressedKey then
            if pressedKey == "DEL" then value = string.sub(value, 1, math.max(0, #value - 1)); errorMsg = ""; drawField()
            elseif pressedKey == "OK" then if #value > 0 then return value else errorMsg = "Entrez un nom!"; drawField() end
            elseif pressedKey == "CANCEL" then return nil
            elseif #value < 12 then value = value .. pressedKey; errorMsg = ""; drawField() end
        end
    end
end

local function getNumpadInput(ctx, title, isMasked, allowCancel)
    local value, errorMsg = "", ""
    clr(ctx); clearButtons(ctx)

    local btnW = math.floor((ctx.w - 4) / 3)
    local bH, gapY, startY = (ctx.h < 18) and 1 or 2, (ctx.h < 18) and 0 or 1, 5
    local padKeys = {{"1","2","3"},{"4","5","6"},{"7","8","9"},{"DEL","0","OK"}}

    for r, row in ipairs(padKeys) do
        for c, keyText in ipairs(row) do
            local bg = (ctx.isColor and colors.cyan or colors.white)
            if keyText == "DEL" then bg = (ctx.isColor and colors.orange or colors.white)
            elseif keyText == "OK" then bg = (ctx.isColor and colors.green or colors.white) end
            addButton(ctx, "k"..keyText, keyText, 2 + (c - 1) * (btnW + 1), startY + (r - 1) * (bH + gapY), btnW, bH, bg, colors.black, function() return keyText end)
        end
    end
    if allowCancel then
        local cancelY = startY + 4 * (bH + gapY)
        if cancelY < ctx.h then addButton(ctx, "cancel", "Annuler", 2, cancelY, ctx.w - 3, 1, (ctx.isColor and colors.red or colors.white), colors.white, function() return "CANCEL" end) end
    end

    drawButtons(ctx); drawFooter(ctx, "Saisir Code / Montant")

    local function drawField()
        ctx.t.setCursorPos(2, 3); ctx.t.setBackgroundColor(colors.black); ctx.t.setTextColor(colors.yellow)
        local dVal = isMasked and string.rep("*", #value) or value
        ctx.t.write(string.sub(" " .. dVal .. string.rep(" ", math.max(0, ctx.w - 2 - #dVal - 1)), 1, ctx.w - 2))
        ctx.t.setCursorPos(2, 4)
        if errorMsg ~= "" then
            ctx.t.setTextColor(ctx.isColor and colors.red or colors.white); ctx.t.setBackgroundColor(ctx.isColor and colors.gray or colors.black)
            ctx.t.write(string.sub(errorMsg .. string.rep(" ", ctx.w), 1, ctx.w - 2))
        else
            ctx.t.setBackgroundColor(ctx.isColor and colors.gray or colors.black); ctx.t.write(string.rep(" ", ctx.w - 2))
        end
    end

    drawHeader(ctx, title); drawField()

    while true do
        local evType, p1, p2 = pullCtxEvent(ctx)
        local pressedKey = nil
        if evType == "tick" then drawHeader(ctx, title)
        elseif evType == "touch" then local cb = handleTouch(ctx, p1, p2); if cb then pressedKey = cb() end
        elseif evType == "char" and string.match(p1, "[0-9]") then pressedKey = p1
        elseif evType == "key" then
            if p1 == keys.backspace then pressedKey = "DEL" elseif p1 == keys.enter or p1 == keys.numPadEnter then pressedKey = "OK" end
        end

        if pressedKey then
            if pressedKey == "DEL" then value = string.sub(value, 1, math.max(0, #value - 1)); errorMsg = ""; drawField()
            elseif pressedKey == "OK" then if #value > 0 then return value else errorMsg = "Valeur vide!"; drawField() end
            elseif pressedKey == "CANCEL" then return nil
            elseif #value < 8 then value = value .. pressedKey; errorMsg = ""; drawField() end
        end
    end
end

-- ====================================================
-- 6. TERMINAL PRINCIPAL (ATM)
-- ====================================================
local function runAtmTerminal(target_term, target_name, drive_name)
    local ctx = createContext(target_term, target_name, drive_name)

    while true do
        local currentAccountName = nil
        
        while not currentAccountName do
            clr(ctx); clearButtons(ctx)
            drawHeader(ctx, "BankOS - Accueil")
            
            local rawCardId, cardSide = getInsertedCardId(ctx.drive)
            local btnW = ctx.w - 4
            
            if rawCardId and rawCardId ~= "UNLINKED" then
                local cardAcc = getAccountByCard(rawCardId)
                if cardAcc then
                    currentAccountName = cardAcc
                    break
                else
                    drawFooter(ctx, "Carte non reconnue")
                    ctx.t.setCursorPos(2, 4); ctx.t.setTextColor(colors.red); ctx.t.write("Carte Inconnue")
                end
            else
                drawFooter(ctx, "Inserez votre carte bancaire")
                
                ctx.t.setBackgroundColor(ctx.isColor and colors.black or colors.gray)
                ctx.t.setTextColor(colors.cyan)
                ctx.t.setCursorPos(2, 3)
                ctx.t.write("=== DISTRIBUTEUR ATM ===")
                
                addButton(ctx, "btn_log", "Se Connecter", 2, 6, btnW, 2, (ctx.isColor and colors.green or colors.white), colors.black, function() return "login" end)
                addButton(ctx, "btn_reg", "S'inscrire", 2, 9, btnW, 2, (ctx.isColor and colors.cyan or colors.white), colors.black, function() return "register" end)
            end
            
            drawButtons(ctx)
            
            local action = nil
            while not action do
                local evType, p1, p2 = pullCtxEvent(ctx)
                if evType == "tick" then 
                    drawHeader(ctx, "BankOS - Accueil")
                elseif evType == "disk_change" then
                    break
                elseif evType == "touch" then
                    local cb = handleTouch(ctx, p1, p2)
                    if cb then action = cb() end
                end
            end

            if action == "login" then
                local nameInput = getAzertyInput(ctx, "ID Compte", true)
                if nameInput then
                    local realAccountName = getAccountByName(nameInput)
                    if realAccountName then
                        local pinInput = getNumpadInput(ctx, "Code PIN", true, true)
                        if pinInput == bankData.accounts[realAccountName].pin then
                            currentAccountName = realAccountName
                        elseif pinInput then
                            clr(ctx); drawHeader(ctx, "Erreur"); ctx.t.setCursorPos(2,3); ctx.t.setTextColor(colors.red); ctx.t.write("PIN Incorrect"); sleep(1.5)
                        end
                    else
                        clr(ctx); drawHeader(ctx, "Erreur"); ctx.t.setCursorPos(2,3); ctx.t.setTextColor(colors.red); ctx.t.write("Compte Inconnu"); sleep(1.5)
                    end
                end
                
            elseif action == "register" then
                local nameInput = getAzertyInput(ctx, "Nouveau Nom", true)
                if nameInput then
                    if getAccountByName(nameInput) then
                        clr(ctx); drawHeader(ctx, "Erreur"); ctx.t.setCursorPos(2,3); ctx.t.setTextColor(colors.red); ctx.t.write("Ce nom existe deja"); sleep(1.5)
                    else
                        local pinInput = getNumpadInput(ctx, "Nouveau PIN", true, true)
                        if pinInput then
                            bankData.accounts[nameInput] = { pin = pinInput, balance = 0, cardHash = nil, history = {} }
                            saveData()
                            logTransaction("SYSTEME", "Creation compte: " .. nameInput)
                            clr(ctx); drawHeader(ctx, "Succes"); ctx.t.setCursorPos(2,3); ctx.t.setTextColor(colors.lime); ctx.t.write("Compte cree !"); sleep(1.5)
                            currentAccountName = nameInput
                        end
                    end
                end
            end
        end

        local function runDashboard()
            while true do
                local rawCardId = getInsertedCardId(ctx.drive)
                if rawCardId and rawCardId ~= "UNLINKED" then
                    local cardAcc = getAccountByCard(rawCardId)
                    if cardAcc and cardAcc ~= currentAccountName then
                        currentAccountName = cardAcc
                    end
                end

                local acc = bankData.accounts[currentAccountName]
                clr(ctx); clearButtons(ctx)
                
                -- Widget Carte / Solde
                ctx.t.setBackgroundColor(colors.black)
                for y = 3, 6 do 
                    ctx.t.setCursorPos(2, y)
                    ctx.t.write(string.rep(" ", ctx.w - 2)) 
                end
                
                ctx.t.setCursorPos(3, 3)
                ctx.t.setTextColor(colors.lightBlue)
                ctx.t.write("TITULAIRE : ")
                ctx.t.setTextColor(colors.white)
                ctx.t.write(string.sub(currentAccountName, 1, ctx.w - 15))

                ctx.t.setCursorPos(3, 4)
                ctx.t.setTextColor(colors.gray)
                ctx.t.write(string.rep("-", ctx.w - 4))

                ctx.t.setCursorPos(3, 5)
                ctx.t.setTextColor(colors.lightGray)
                ctx.t.write("SOLDE DISPONIBLE :")

                ctx.t.setCursorPos(3, 6)
                ctx.t.setTextColor(colors.lime)
                ctx.t.write("$ " .. string.format("%.2f", acc.balance))

                local colW = math.floor((ctx.w - 5) / 2)
                local col1X = 2
                local col2X = 2 + colW + 1

                addButton(ctx, "dep", "+ Depot", col1X, 8, colW, 2, (ctx.isColor and colors.green or colors.white), colors.black, function() return "depot" end)
                addButton(ctx, "tra", "-> Transfert", col1X, 11, colW, 2, (ctx.isColor and colors.purple or colors.white), colors.white, function() return "transfert" end)
                addButton(ctx, "his", "Historique", col1X, 14, colW, 2, (ctx.isColor and colors.lightBlue or colors.white), colors.black, function() return "history" end)

                addButton(ctx, "ret", "- Retrait", col2X, 8, colW, 2, (ctx.isColor and colors.orange or colors.white), colors.black, function() return "retrait" end)
                addButton(ctx, "crd", "Lier Carte", col2X, 11, colW, 2, (ctx.isColor and colors.yellow or colors.white), colors.black, function() return "card" end)
                addButton(ctx, "chpin", "Modifier PIN", col2X, 14, colW, 2, (ctx.isColor and colors.cyan or colors.white), colors.black, function() return "change_pin" end)

                addButton(ctx, "quit", "Deconnexion", 2, 17, ctx.w - 3, 1, (ctx.isColor and colors.red or colors.white), colors.white, function() return "logout" end)

                drawButtons(ctx); drawFooter(ctx, "Session : " .. currentAccountName)

                while true do
                    drawHeader(ctx, "BankOS - Dashboard")
                    local evType, p1, p2 = pullCtxEvent(ctx)
                    
                    if evType == "tick" or evType == "disk_change" then
                        break
                    elseif evType == "touch" then
                        local cb = handleTouch(ctx, p1, p2)
                        if cb then
                            local a = cb()
                            if a == "logout" then return end
                            
                            if a == "change_pin" then
                                local newPin = getNumpadInput(ctx, "Nouveau PIN", true, true)
                                if newPin then
                                    bankData.accounts[currentAccountName].pin = newPin
                                    saveData()
                                    logTransaction(currentAccountName, "PIN modifie")
                                    clr(ctx); drawHeader(ctx, "Succes"); ctx.t.setCursorPos(2,3); ctx.t.setTextColor(colors.lime); ctx.t.write("PIN mis a jour !"); sleep(1.5)
                                end
                                break

                            elseif a == "depot" then
                                local val = getNumpadInput(ctx, "Montant Depot", false, true)
                                local amt = tonumber(val)
                                if amt and amt > 0 then
                                    bankData.accounts[currentAccountName].balance = acc.balance + amt
                                    logTransaction(currentAccountName, "+$"..amt.." (Depot)")
                                end
                                break 
                                
                            elseif a == "retrait" then
                                local val = getNumpadInput(ctx, "Montant Retrait", false, true)
                                local amt = tonumber(val)
                                if amt and amt > 0 then
                                    if acc.balance >= amt then
                                        bankData.accounts[currentAccountName].balance = acc.balance - amt
                                        logTransaction(currentAccountName, "-$"..amt.." (Retrait)")
                                    else
                                        clr(ctx); drawHeader(ctx, "Erreur"); ctx.t.setCursorPos(2,3); ctx.t.setTextColor(colors.red); ctx.t.write("Fonds insuffisants"); sleep(1.5)
                                    end
                                end
                                break

                            elseif a == "transfert" then
                                local targetInput = getAzertyInput(ctx, "Destinataire", true)
                                if targetInput then
                                    local realTarget = getAccountByName(targetInput)
                                    if not realTarget then
                                        clr(ctx); drawHeader(ctx, "Erreur"); ctx.t.setCursorPos(2,3); ctx.t.setTextColor(colors.red); ctx.t.write("Compte introuvable"); sleep(1.5)
                                    elseif string.lower(realTarget) == string.lower(currentAccountName) then
                                        clr(ctx); drawHeader(ctx, "Erreur"); ctx.t.setCursorPos(2,3); ctx.t.setTextColor(colors.red); ctx.t.write("Transfert impossible"); sleep(1.5)
                                    else
                                        local val = getNumpadInput(ctx, "Montant Virement", false, true)
                                        local amt = tonumber(val)
                                        if amt and amt > 0 then
                                            if acc.balance >= amt then
                                                bankData.accounts[currentAccountName].balance = acc.balance - amt
                                                bankData.accounts[realTarget].balance = bankData.accounts[realTarget].balance + amt
                                                logTransaction(currentAccountName, "-$"..amt.." -> " .. realTarget)
                                                logTransaction(realTarget, "+$"..amt.." <- " .. currentAccountName)
                                                clr(ctx); drawHeader(ctx, "Succes"); ctx.t.setCursorPos(2,3); ctx.t.setTextColor(colors.lime); ctx.t.write("Virement effectue !"); sleep(1.5)
                                            else
                                                clr(ctx); drawHeader(ctx, "Erreur"); ctx.t.setCursorPos(2,3); ctx.t.setTextColor(colors.red); ctx.t.write("Fonds insuffisants"); sleep(1.5)
                                            end
                                        end
                                    end
                                end
                                break

                            elseif a == "history" then
                                clr(ctx); clearButtons(ctx)
                                drawHeader(ctx, "Mes Transactions")
                                addButton(ctx, "back", "Retour", 2, ctx.h - 1, ctx.w - 3, 1, colors.gray, colors.white, function() return "back" end)
                                drawButtons(ctx)
                                
                                local hList = bankData.accounts[currentAccountName].history or {}
                                local yPos = 3
                                for i = #hList, 1, -1 do
                                    if yPos >= ctx.h - 2 then break end
                                    ctx.t.setCursorPos(2, yPos)
                                    local item = hList[i]
                                    if string.find(item, "%+") then ctx.t.setTextColor(colors.lime)
                                    elseif string.find(item, "%-") then ctx.t.setTextColor(colors.orange)
                                    else ctx.t.setTextColor(colors.white) end
                                    ctx.t.write(string.sub(item, 1, ctx.w - 2))
                                    yPos = yPos + 1
                                end
                                
                                while true do
                                    local evType, p1, p2 = pullCtxEvent(ctx)
                                    if evType == "touch" and handleTouch(ctx, p1, p2) then break end
                                end
                                break

                            elseif a == "card" then
                                local cId, side = getInsertedCardId(ctx.drive)
                                if side then
                                    local rawCardId = generateCardCode()
                                    local cardHash = hashCardCode(rawCardId)
                                    if writeCardId(side, rawCardId) then
                                        bankData.accounts[currentAccountName].cardHash = cardHash
                                        saveData()
                                        clr(ctx); drawHeader(ctx, "Succes"); ctx.t.setCursorPos(2,3); ctx.t.setTextColor(colors.lime); ctx.t.write("Carte liee !"); sleep(1.5)
                                    else
                                        clr(ctx); drawHeader(ctx, "Erreur"); ctx.t.setCursorPos(2,3); ctx.t.setTextColor(colors.red); ctx.t.write("Erreur d'ecriture"); sleep(1.5)
                                    end
                                else
                                    clr(ctx); drawHeader(ctx, "Erreur"); ctx.t.setCursorPos(2,3); ctx.t.setTextColor(colors.red); ctx.t.write("Inserez disquette"); sleep(1.5)
                                end
                                break
                            end
                        end
                    end
                end
            end
        end
        
        runDashboard()
    end
end

-- ====================================================
-- 7. SERVEUR DE LOG ET API REDNET (ECRAN INTERNE)
-- ====================================================
local function runServerLogAndAPI()
    term.redirect(term.native())
    local w, h = term.getSize()
    
    local modem = peripheral.find("modem")
    if modem then rednet.open(peripheral.getName(modem)) end

    local function drawLogs()
        term.setBackgroundColor(colors.black); term.clear()
        term.setCursorPos(1,1); term.setBackgroundColor(colors.blue); term.setTextColor(colors.white); term.clearLine()
        term.write(" LOGS SERVEUR & API CRYPTEE")
        
        term.setBackgroundColor(colors.black)
        local startY = 3
        for i = #globalHistory, math.max(1, #globalHistory - (h - 4)), -1 do
            term.setCursorPos(2, startY)
            local log = globalHistory[i]
            if string.find(log, "%+") then term.setTextColor(colors.lime)
            elseif string.find(log, "%-") then term.setTextColor(colors.red)
            else term.setTextColor(colors.lightGray) end
            term.write(log)
            startY = startY + 1
        end
    end

    drawLogs()

    while true do
        local ev, p1, p2 = os.pullEvent()
        
        if ev == "bank_update" then 
            drawLogs()
            
        elseif ev == "rednet_message" then
            local senderId, encryptedMsg = p1, p2
            if type(encryptedMsg) == "string" then
                local decryptedMsg = cipher(encryptedMsg, MASTER_KEY)
                local req = textutils.unserialize(decryptedMsg)
                
                if req and req.type == "PAYMENT" then
                    local accName = getAccountByName(req.account)
                    local resp = { success = false, message = "Erreur" }
                    
                    if accName and bankData.accounts[accName].pin == req.pin then
                        if bankData.accounts[accName].balance >= req.amount then
                            bankData.accounts[accName].balance = bankData.accounts[accName].balance - req.amount
                            if req.target then
                                local targetAcc = getAccountByName(req.target)
                                if targetAcc then
                                    bankData.accounts[targetAcc].balance = bankData.accounts[targetAcc].balance + req.amount
                                    logTransaction(targetAcc, "+$"..req.amount.." <- " .. accName)
                                end
                            end
                            logTransaction(accName, "-$"..req.amount.." (Paiement API)")
                            resp.success = true
                            resp.message = "Paiement valide"
                        else
                            resp.message = "Fonds insuffisants"
                        end
                    else
                        resp.message = "Identifiants invalides"
                    end
                    
                    local replyEncrypted = cipher(textutils.serialize(resp), MASTER_KEY)
                    rednet.send(senderId, replyEncrypted)
                end
            end
        end
    end
end

-- ====================================================
-- LANCEMENT DU SYSTEME (1 ATM EXTERNE + 1 SERVEUR INTERNE)
-- ====================================================
loadData()

local tasks = {}

table.insert(tasks, function()
    while true do
        sleep(1)
        os.queueEvent("bank_tick")
    end
end)

table.insert(tasks, runServerLogAndAPI)

local monitor = peripheral.find("monitor")
local drive = peripheral.find("drive")
local driveName = drive and peripheral.getName(drive) or nil

if monitor then
    local monitorName = peripheral.getName(monitor)
    monitor.setTextScale(0.5)
    table.insert(tasks, function() runAtmTerminal(monitor, monitorName, driveName) end)
else
    table.insert(tasks, function() runAtmTerminal(term.native(), "computer", driveName) end)
end

parallel.waitForAll(table.unpack(tasks))
