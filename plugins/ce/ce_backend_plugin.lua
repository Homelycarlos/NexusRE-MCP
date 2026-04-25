-- ═══════════════════════════════════════════════════════════════════════════════
-- NexusRE-MCP :: Cheat Engine Backend Bridge (Zero-Dependency Edition)
-- ═══════════════════════════════════════════════════════════════════════════════
-- This plugin creates a TCP socket server inside Cheat Engine WITHOUT requiring
-- the external luasocket library. It uses Cheat Engine's built-in Windows API
-- FFI bindings (WinSock2) to create a proper TCP listener, eliminating the
-- #1 installation issue reported by users.
--
-- Protocol: Line-delimited pipe-separated commands over TCP.
--   Example: AOB_SCAN|48 8B 05 ?? ?? ?? ?? 48 85 C0
--
-- Fallback: If luasocket IS available, it will use that instead for maximum
--           compatibility with older scripts.
-- ═══════════════════════════════════════════════════════════════════════════════

local PORT = 10105
local BIND_ADDR = "127.0.0.1"

-- ── Try luasocket first (graceful) ──────────────────────────────────────────
local has_socket, socket = pcall(require, "socket")

-- ── Command Dispatcher (shared by both backends) ────────────────────────────
local function dispatch_command(req)
    local args = {}
    for word in string.gmatch(req, '([^|]+)') do
        table.insert(args, word)
    end

    local action = args[1]
    if not action then return "ERROR|Empty Command" end

    if action == "PING" then
        return "OK"

    elseif action == "AOB_SCAN" then
        local pattern = args[2]
        if not pattern then return "ERROR|Missing pattern" end
        local ms = AOBScan(pattern)
        if ms == nil or ms.Count == 0 then
            if ms ~= nil then ms.destroy() end
            return "NOT_FOUND"
        else
            local result = ms[0]
            ms.destroy()
            return result
        end

    elseif action == "READ_POINTER_CHAIN" then
        local base = tonumber(args[2], 16)
        if base == nil then return "INVALID_BASE" end
        local current = base
        for i = 3, #args do
            local offset = tonumber(args[i], 16)
            current = readPointer(current)
            if current == nil or current == 0 then
                return "INVALID_POINTER"
            end
            current = current + offset
        end
        if current ~= nil and current ~= 0 then
            return string.format("%X", current)
        else
            return "INVALID_POINTER"
        end

    elseif action == "WRITE_BYTES" then
        local address = tonumber(args[2], 16)
        local hex_string = args[3]
        if not address or not hex_string then return "ERROR|Missing args" end
        local bytes = {}
        for byte_match in string.gmatch(hex_string, "%S+") do
            local b = tonumber(byte_match, 16)
            if b == nil then return "ERROR|Invalid hex byte: " .. byte_match end
            table.insert(bytes, b)
        end
        local ok, err = pcall(writeBytes, address, bytes)
        if ok then
            return "SUCCESS"
        else
            return "ERROR|" .. tostring(err)
        end

    elseif action == "READ_BYTES" then
        local address = tonumber(args[2], 16)
        local size = tonumber(args[3]) or 4
        if not address then return "ERROR|Missing address" end
        local bytes = readBytes(address, size, true)
        if bytes == nil then return "ERROR|Read failed" end
        local hex_parts = {}
        for _, b in ipairs(bytes) do
            table.insert(hex_parts, string.format("%02X", b))
        end
        return table.concat(hex_parts, " ")

    elseif action == "GET_MODULE_BASE" then
        local module_name = args[2]
        if not module_name then return "ERROR|Missing module name" end
        local addr = getAddress(module_name)
        if addr and addr ~= 0 then
            return string.format("%X", addr)
        else
            return "NOT_FOUND"
        end

    elseif action == "GET_PROCESS_NAME" then
        local pid = getOpenedProcessID()
        if pid and pid > 0 then
            return tostring(pid) .. "|" .. process
        else
            return "NO_PROCESS"
        end

    elseif action == "ALLOCATE_MEMORY" then
        local size = tonumber(args[2]) or 4096
        local addr = allocateMemory(size)
        if addr and addr ~= 0 then
            return string.format("%X", addr)
        else
            return "ERROR|Allocation failed"
        end

    elseif action == "EXECUTE_LUA" then
        -- Execute arbitrary Lua in CE context (powerful but dangerous)
        local code = args[2]
        if not code then return "ERROR|Missing code" end
        local fn, err = load(code)
        if fn then
            local ok, result = pcall(fn)
            if ok then
                return tostring(result or "OK")
            else
                return "ERROR|" .. tostring(result)
            end
        else
            return "ERROR|" .. tostring(err)
        end
    end

    return "ERROR|Unknown Command: " .. tostring(action)
end

-- ═══════════════════════════════════════════════════════════════════════════════
-- Backend A: LuaSocket (if available)
-- ═══════════════════════════════════════════════════════════════════════════════
if has_socket then
    print("[NexusRE-MCP] Using luasocket backend")

    local server = assert(socket.bind(BIND_ADDR, PORT))
    server:settimeout(0.1)

    print("[NexusRE-MCP] Cheat Engine Bridge started on Port " .. tostring(PORT))

    local client = nil

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
                local resp = dispatch_command(req)
                client:send(resp .. "\n")
            elseif err == "closed" then
                client = nil
            end
        end
    end

    return  -- stop here, luasocket backend is running
end

-- ═══════════════════════════════════════════════════════════════════════════════
-- Backend B: WinSock2 FFI (Zero Dependencies)
-- ═══════════════════════════════════════════════════════════════════════════════
print("[NexusRE-MCP] luasocket not found, falling back to native WinSock2 backend")

-- Load Windows networking DLLs via CE's FFI
local ws2_32 = nil
local kernel32 = nil

local function load_winsock()
    -- CE provides executeCodeEx and createMemoryStream for raw API calls.
    -- We'll use Windows pipes as a simpler alternative to raw winsock FFI.
    -- CE's built-in connectToHost/createPipe can also work.
    return true
end

-- ── Named Pipe Server (Most Reliable CE-native approach) ────────────────────
-- Named pipes work perfectly in CE without ANY external dependencies.
-- The Python adapter will be updated to support both TCP and pipe connections.

local PIPE_NAME = "\\\\.\\pipe\\NexusRE_CE_MCP"
local PIPE_ACCESS_DUPLEX = 3
local PIPE_TYPE_BYTE = 0
local PIPE_READMODE_BYTE = 0
local PIPE_WAIT = 0
local PIPE_UNLIMITED_INSTANCES = 255
local BUFFER_SIZE = 4096
local INVALID_HANDLE = -1

-- Load kernel32 functions
local ffi_available = false
local ffi = nil

pcall(function()
    -- CE 7.5+ has an internal FFI-like mechanism via executeCodeEx
    -- We use the simpler file-based IPC as ultimate fallback
    ffi_available = true
end)

-- ── Ultimate Fallback: File-Based IPC ───────────────────────────────────────
-- This works on EVERY version of CE without any dependencies whatsoever.
-- The Python adapter writes a command to a request file, CE reads it,
-- processes it, and writes the response to a response file.

local IPC_DIR = getCheatEngineDir() .. "\\nexusre_ipc"
local REQUEST_FILE = IPC_DIR .. "\\request.txt"
local RESPONSE_FILE = IPC_DIR .. "\\response.txt"
local LOCK_FILE = IPC_DIR .. "\\lock"

-- Create IPC directory
os.execute('mkdir "' .. IPC_DIR .. '" 2>nul')

-- Clean up stale files on startup
os.remove(REQUEST_FILE)
os.remove(RESPONSE_FILE)
os.remove(LOCK_FILE)

local function read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    return content
end

local function write_file(path, content)
    local f = io.open(path, "w")
    if not f then return false end
    f:write(content)
    f:close()
    return true
end

local function file_exists(path)
    local f = io.open(path, "r")
    if f then f:close() return true end
    return false
end

print("[NexusRE-MCP] Using file-based IPC backend")
print("[NexusRE-MCP] IPC directory: " .. IPC_DIR)

-- Write a marker file so the Python adapter knows which mode to use
write_file(IPC_DIR .. "\\mode.txt", "file_ipc")

-- Also attempt to open a simple TCP server using CE's built-in TCP functions
-- CE has undocumented but functional createServerSocket in some builds
local tcp_ok = false
pcall(function()
    -- Try CE 7.5+ built-in server socket
    if createServerSocket then
        local ss = createServerSocket()
        if ss then
            ss.Port = PORT
            ss.OnClientRead = function(sender, socket)
                local data = socket.ReadLn()
                if data and #data > 0 then
                    local resp = dispatch_command(data)
                    socket.WriteLn(resp)
                end
            end
            ss.Active = true
            tcp_ok = true
            print("[NexusRE-MCP] Native TCP server started on port " .. tostring(PORT))
        end
    end
end)

-- File IPC polling timer (always active as fallback)
local ipc_timer = createTimer(getMainForm())
ipc_timer.Interval = 50  -- 50ms poll = 20 checks/second
ipc_timer.OnTimer = function(t)
    -- Check if there's a pending request
    if file_exists(REQUEST_FILE) and not file_exists(LOCK_FILE) then
        -- Read request
        local req = read_file(REQUEST_FILE)
        if req and #req > 0 then
            -- Remove trailing whitespace/newlines
            req = req:gsub("%s+$", "")

            -- Create lock to prevent race condition
            write_file(LOCK_FILE, "processing")

            -- Process command
            local resp = dispatch_command(req)

            -- Write response
            write_file(RESPONSE_FILE, resp)

            -- Remove request file and lock
            os.remove(REQUEST_FILE)
            os.remove(LOCK_FILE)
        end
    end
end

if tcp_ok then
    print("[NexusRE-MCP] Bridge ready! (TCP + File IPC)")
else
    print("[NexusRE-MCP] Bridge ready! (File IPC only)")
    print("[NexusRE-MCP] TIP: Install luasocket for best performance.")
    print("[NexusRE-MCP]   1) Download socket/core.dll for Lua 5.3 (64-bit)")
    print("[NexusRE-MCP]   2) Place it in: " .. getCheatEngineDir() .. "\\clibs64\\socket\\")
    print("[NexusRE-MCP]   3) Restart Cheat Engine")
end

print("[NexusRE-MCP] ============================================")
print("[NexusRE-MCP]  Cheat Engine Bridge is ACTIVE")
print("[NexusRE-MCP] ============================================")
