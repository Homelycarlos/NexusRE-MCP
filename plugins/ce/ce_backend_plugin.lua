-- NexusRE Cheat Engine MCP Bridge
-- Listens on Port 10105 for raw TCP commands

local port = 10105

function OnClientExecute(thread, context)
  local client = context.Connection
  while client.Connected do
    local req = client.IOHandler.ReadLn()
    if req ~= "" and req ~= nil then
      -- Parse simple custom protocol since Lua JSON is annoying without libraries
      -- Format: ACTION|ARG1|ARG2|ARG3
      local args = {}
      for word in string.gmatch(req, '([^|]+)') do
        table.insert(args, word)
      end
      
      local action = args[1]
      local resp = "ERROR|Unknown Command"
      
      if action == "PING" then
        resp = "OK"
      
      elseif action == "GET_PROCESS" then
        if getOpenedProcessID() == 0 then
          resp = "NONE"
        else
          resp = "PID:"..tostring(getOpenedProcessID())
        end

      elseif action == "AOB_SCAN" then
        local pattern = args[2]
        local ms = AOBScan(pattern)
        if ms == nil then
          resp = "NOT_FOUND"
        else
          -- Just return the first matched address for simplicity
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
        -- hex2bytes loop equivalent
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
      
      client.IOHandler.WriteLn(resp)
    end
  end
end

if Server ~= nil then Server.destroy() end

Server = createIdTCPServer(nil)
Server.DefaultPort = port
Server.OnExecute = OnClientExecute
Server.Active = true

print("[NexusRE MCP] Cheat Engine Bridge started on Port " .. tostring(port))
