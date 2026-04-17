local socket = require("socket")
local port = 10105

local server = assert(socket.bind("127.0.0.1", port))
server:settimeout(0.1)

print("[NexusRE MCP] Cheat Engine Bridge started on Port " .. tostring(port))

local client = nil

-- We use a CE timer to pump the socket so it doesn't freeze the GUI
local timer = createTimer(getMainForm())
timer.Interval = 100
timer.OnTimer = function(t)
    if not client then
        client = server:accept()
        if client then
            client:settimeout(0.1)
        end
    end

    if client then
        local req, err = client:receive("*l")
        if req then
            local args = {}
            for word in string.gmatch(req, '([^|]+)') do
                table.insert(args, word)
            end
            
            local action = args[1]
            local resp = "ERROR|Unknown Command"
            
            if action == "PING" then
                resp = "OK"
            elseif action == "AOB_SCAN" then
                local pattern = args[2]
                local ms = AOBScan(pattern)
                if ms == nil then
                    resp = "NOT_FOUND"
                else
                    resp = string.format("%X", ms.getString(0))
                    ms.destroy()
                end
            elseif action == "READ_POINTER_CHAIN" then
                local base = tonumber(args[2], 16)
                local chain_len = #args
                local current = base
                if current ~= nil then
                    for i=3, chain_len do
                        local offset = tonumber(args[i], 16)
                        current = readPointer(current)
                        if current == nil or current == 0 then
                            break
                        end
                        current = current + offset
                    end
                    if current ~= nil and current ~= 0 then
                        resp = string.format("%X", current)
                    else
                        resp = "INVALID_POINTER"
                    end
                else
                    resp = "INVALID_BASE"
                end
            elseif action == "WRITE_BYTES" then
                local address = tonumber(args[2], 16)
                local hex_string = args[3]
                local bytes = {}
                for bytes_match in string.gmatch(hex_string, "%S+") do
                    table.insert(bytes, tonumber(bytes_match, 16))
                end
                if writeBytes(address, bytes) then
                    resp = "SUCCESS"
                else
                    resp = "FAILED"
                end
            end
            
            client:send(resp .. "\n")
        elseif err == "closed" then
            client = nil
        end
    end
end
