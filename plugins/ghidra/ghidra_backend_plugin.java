//NexusRE-MCP Ghidra Backend Plugin v2 (Java Edition)
//Works on ALL Ghidra installations — no PyGhidra required.
//Starts a background HTTP server on port 10102 for AI connectivity.
//@author NexusRE
//@category NexusRE
//@menupath Tools.NexusRE MCP Server

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.util.DefinedDataIterator;
import com.google.gson.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

public class ghidra_backend_plugin extends GhidraScript {

    private static HttpServer server = null;
    private static Program programRef = null;
    private static final int PORT = 10102;

    @Override
    public void run() throws Exception {
        programRef = currentProgram;

        if (server != null) {
            println("[NexusRE-MCP] Shutting down previous server...");
            server.stop(0);
        }

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", PORT), 0);
        server.createContext("/", new MCPHandler());
        server.setExecutor(null);
        server.start();

        println("[NexusRE-MCP] ============================================");
        println("[NexusRE-MCP]  Ghidra Java Backend LIVE on port " + PORT);
        println("[NexusRE-MCP]  Program: " + (programRef != null ? programRef.getName() : "none"));
        println("[NexusRE-MCP] ============================================");

        // Keep script alive
        while (!monitor.isCancelled()) {
            Thread.sleep(1000);
            // Validate program ref
            if (programRef != null) {
                try { programRef.getName(); }
                catch (Exception e) { programRef = null; }
            }
        }
        server.stop(0);
        println("[NexusRE-MCP] Server stopped.");
    }

    static class MCPHandler implements HttpHandler {
        private Gson gson = new GsonBuilder().serializeNulls().create();

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();

            if ("GET".equalsIgnoreCase(method)) {
                JsonObject resp = new JsonObject();
                resp.addProperty("status", programRef != null ? "ok" : "no_program");
                resp.addProperty("program", programRef != null ? programRef.getName() : "");
                sendJson(exchange, 200, resp);
                return;
            }

            if (!"POST".equalsIgnoreCase(method)) {
                sendJson(exchange, 405, errorJson("Method not allowed"));
                return;
            }

            // Read body
            InputStream is = exchange.getRequestBody();
            String body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            if (body.isEmpty()) {
                sendJson(exchange, 400, errorJson("Empty body"));
                return;
            }

            JsonObject req;
            try { req = JsonParser.parseString(body).getAsJsonObject(); }
            catch (Exception e) {
                sendJson(exchange, 400, errorJson("Bad JSON: " + e.getMessage()));
                return;
            }

            String action = req.has("action") ? req.get("action").getAsString() : "";
            JsonObject args = req.has("args") ? req.getAsJsonObject("args") : new JsonObject();

            try {
                JsonObject result = dispatch(action, args);
                sendJson(exchange, 200, result);
            } catch (Exception e) {
                JsonObject err = new JsonObject();
                err.addProperty("error_message", e.toString());
                err.addProperty("error_code", "INTERNAL");
                sendJson(exchange, 500, err);
            }
        }

        private JsonObject dispatch(String action, JsonObject args) throws Exception {
            Program prog = programRef;
            if (prog == null) return errorJson("No program loaded in Ghidra");

            switch (action) {
                case "ping": {
                    JsonObject r = new JsonObject();
                    r.addProperty("status", "ok");
                    r.addProperty("program", prog.getName());
                    return r;
                }

                case "ghidra_get_current_address": {
                    JsonObject r = new JsonObject();
                    r.add("address", JsonNull.INSTANCE);
                    return r;
                }

                case "ghidra_get_current_function": {
                    JsonObject r = new JsonObject();
                    r.add("address", JsonNull.INSTANCE);
                    return r;
                }

                case "ghidra_list_functions": {
                    int limit = getInt(args, "limit", 100);
                    int offset = getInt(args, "offset", 0);
                    String filt = getStr(args, "filter", null);
                    JsonArray funcs = new JsonArray();
                    FunctionManager fm = prog.getFunctionManager();
                    FunctionIterator it = fm.getFunctions(true);
                    int idx = 0;
                    while (it.hasNext()) {
                        Function f = it.next();
                        String name = f.getName();
                        if (filt != null && !name.toLowerCase().contains(filt.toLowerCase())) continue;
                        if (idx < offset) { idx++; continue; }
                        if (idx >= offset + limit) break;
                        JsonObject fo = new JsonObject();
                        fo.addProperty("name", name);
                        fo.addProperty("address", "0x" + f.getEntryPoint().toString());
                        fo.addProperty("size", (int) f.getBody().getNumAddresses());
                        funcs.add(fo);
                        idx++;
                    }
                    JsonObject r = new JsonObject();
                    r.add("functions", funcs);
                    return r;
                }

                case "ghidra_get_function": {
                    Address addr = resolveAddr(prog, getStr(args, "address", ""));
                    if (addr == null) return errorJson("Invalid address");
                    Function func = prog.getFunctionManager().getFunctionAt(addr);
                    if (func == null) func = prog.getFunctionManager().getFunctionContaining(addr);
                    if (func == null) return errorJson("Function not found");
                    JsonObject r = new JsonObject();
                    r.addProperty("name", func.getName());
                    r.addProperty("address", "0x" + func.getEntryPoint().toString());
                    r.addProperty("size", (int) func.getBody().getNumAddresses());
                    return r;
                }

                case "ghidra_decompile_function": {
                    Address addr = resolveAddr(prog, getStr(args, "address", ""));
                    if (addr == null) return errorJson("Invalid address");
                    Function func = prog.getFunctionManager().getFunctionAt(addr);
                    if (func == null) func = prog.getFunctionManager().getFunctionContaining(addr);
                    if (func == null) return errorJson("Function not found");
                    DecompInterface decomp = new DecompInterface();
                    decomp.openProgram(prog);
                    DecompileResults res = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());
                    JsonObject r = new JsonObject();
                    if (res != null && res.getDecompiledFunction() != null) {
                        r.addProperty("code", res.getDecompiledFunction().getC());
                    } else {
                        r.addProperty("code", "// Decompilation failed");
                    }
                    decomp.dispose();
                    return r;
                }

                case "ghidra_batch_decompile": {
                    JsonArray addrs = args.has("addresses") ? args.getAsJsonArray("addresses") : new JsonArray();
                    DecompInterface decomp = new DecompInterface();
                    decomp.openProgram(prog);
                    JsonObject results = new JsonObject();
                    for (int i = 0; i < addrs.size(); i++) {
                        String aStr = addrs.get(i).getAsString();
                        Address addr = resolveAddr(prog, aStr);
                        if (addr == null) { results.addProperty(aStr, "// Invalid address"); continue; }
                        Function func = prog.getFunctionManager().getFunctionAt(addr);
                        if (func == null) func = prog.getFunctionManager().getFunctionContaining(addr);
                        if (func == null) { results.addProperty(aStr, "// No function"); continue; }
                        DecompileResults res = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());
                        if (res != null && res.getDecompiledFunction() != null) {
                            results.addProperty(aStr, res.getDecompiledFunction().getC());
                        } else {
                            results.addProperty(aStr, "// Failed");
                        }
                    }
                    decomp.dispose();
                    JsonObject r = new JsonObject();
                    r.add("results", results);
                    return r;
                }

                case "ghidra_disassemble": {
                    Address addr = resolveAddr(prog, getStr(args, "address", ""));
                    if (addr == null) return errorJson("Invalid address");
                    Function func = prog.getFunctionManager().getFunctionAt(addr);
                    if (func == null) func = prog.getFunctionManager().getFunctionContaining(addr);
                    if (func == null) {
                        JsonObject r = new JsonObject();
                        r.addProperty("code", "// No function at address");
                        return r;
                    }
                    Listing listing = prog.getListing();
                    StringBuilder sb = new StringBuilder();
                    InstructionIterator it = listing.getInstructions(func.getBody(), true);
                    while (it.hasNext()) {
                        Instruction instr = it.next();
                        sb.append("0x").append(instr.getAddress().toString())
                          .append(": ").append(instr.toString()).append("\n");
                    }
                    JsonObject r = new JsonObject();
                    r.addProperty("code", sb.toString());
                    return r;
                }

                case "ghidra_get_xrefs": {
                    Address addr = resolveAddr(prog, getStr(args, "address", ""));
                    if (addr == null) return errorJson("Invalid address");
                    JsonArray refs = new JsonArray();
                    ReferenceManager rm = prog.getReferenceManager();
                    ReferenceIterator it = rm.getReferencesTo(addr);
                    while (it.hasNext()) {
                        Reference ref = it.next();
                        JsonObject ro = new JsonObject();
                        ro.addProperty("from", "0x" + ref.getFromAddress().toString());
                        ro.addProperty("to", "0x" + ref.getToAddress().toString());
                        ro.addProperty("type", ref.getReferenceType().getName());
                        refs.add(ro);
                    }
                    JsonObject r = new JsonObject();
                    r.add("xrefs", refs);
                    return r;
                }

                case "ghidra_get_strings": {
                    int limit = getInt(args, "limit", 100);
                    int offset = getInt(args, "offset", 0);
                    String filt = getStr(args, "filter", null);
                    JsonArray strings = new JsonArray();
                    int idx = 0;
                    for (Data data : DefinedDataIterator.definedStrings(prog)) {
                        String val = data.getDefaultValueRepresentation();
                        if (filt != null && !val.toLowerCase().contains(filt.toLowerCase())) continue;
                        if (idx < offset) { idx++; continue; }
                        if (idx >= offset + limit) break;
                        JsonObject so = new JsonObject();
                        so.addProperty("address", "0x" + data.getAddress().toString());
                        so.addProperty("value", val);
                        strings.add(so);
                        idx++;
                    }
                    JsonObject r = new JsonObject();
                    r.add("strings", strings);
                    return r;
                }

                case "ghidra_get_segments": {
                    int limit = getInt(args, "limit", 100);
                    int offset = getInt(args, "offset", 0);
                    JsonArray segs = new JsonArray();
                    MemoryBlock[] blocks = prog.getMemory().getBlocks();
                    for (int i = offset; i < Math.min(blocks.length, offset + limit); i++) {
                        MemoryBlock b = blocks[i];
                        String perms = "";
                        if (b.isRead()) perms += "R";
                        if (b.isWrite()) perms += "W";
                        if (b.isExecute()) perms += "X";
                        JsonObject so = new JsonObject();
                        so.addProperty("name", b.getName());
                        so.addProperty("start_address", "0x" + b.getStart().toString());
                        so.addProperty("end_address", "0x" + b.getEnd().toString());
                        so.addProperty("size", (int) b.getSize());
                        so.addProperty("permissions", perms);
                        segs.add(so);
                    }
                    JsonObject r = new JsonObject();
                    r.add("segments", segs);
                    return r;
                }

                case "ghidra_get_imports": {
                    int limit = getInt(args, "limit", 100);
                    int offset = getInt(args, "offset", 0);
                    JsonArray imps = new JsonArray();
                    SymbolTable st = prog.getSymbolTable();
                    SymbolIterator it = st.getExternalSymbols();
                    int idx = 0;
                    while (it.hasNext()) {
                        Symbol sym = it.next();
                        if (idx < offset) { idx++; continue; }
                        if (idx >= offset + limit) break;
                        JsonObject io = new JsonObject();
                        io.addProperty("address", "0x" + sym.getAddress().toString());
                        io.addProperty("name", sym.getName());
                        Namespace parent = sym.getParentNamespace();
                        io.addProperty("module", parent != null ? parent.getName() : "");
                        imps.add(io);
                        idx++;
                    }
                    JsonObject r = new JsonObject();
                    r.add("imports", imps);
                    return r;
                }

                case "ghidra_get_exports": {
                    int limit = getInt(args, "limit", 100);
                    int offset = getInt(args, "offset", 0);
                    JsonArray exps = new JsonArray();
                    SymbolTable st = prog.getSymbolTable();
                    SymbolIterator it = st.getAllSymbols(true);
                    int idx = 0;
                    while (it.hasNext()) {
                        Symbol sym = it.next();
                        if (!sym.isExternalEntryPoint()) continue;
                        if (idx < offset) { idx++; continue; }
                        if (idx >= offset + limit) break;
                        JsonObject eo = new JsonObject();
                        eo.addProperty("address", "0x" + sym.getAddress().toString());
                        eo.addProperty("name", sym.getName());
                        exps.add(eo);
                        idx++;
                    }
                    JsonObject r = new JsonObject();
                    r.add("exports", exps);
                    return r;
                }

                case "ghidra_get_globals": {
                    int limit = getInt(args, "limit", 100);
                    int offset = getInt(args, "offset", 0);
                    String filt = getStr(args, "filter", null);
                    JsonArray globs = new JsonArray();
                    SymbolTable st = prog.getSymbolTable();
                    SymbolIterator it = st.getAllSymbols(true);
                    int idx = 0;
                    while (it.hasNext()) {
                        Symbol sym = it.next();
                        if (sym.isExternal()) continue;
                        String name = sym.getName();
                        if (!name.startsWith("DAT_") && !name.startsWith("s_") && !name.startsWith("u_")) continue;
                        if (filt != null && !name.toLowerCase().contains(filt.toLowerCase())) continue;
                        if (idx < offset) { idx++; continue; }
                        if (idx >= offset + limit) break;
                        JsonObject go = new JsonObject();
                        go.addProperty("address", "0x" + sym.getAddress().toString());
                        go.addProperty("name", name);
                        go.addProperty("size", 0);
                        go.add("value", JsonNull.INSTANCE);
                        globs.add(go);
                        idx++;
                    }
                    JsonObject r = new JsonObject();
                    r.add("globals", globs);
                    return r;
                }

                // ── Write Operations (with transactions) ──

                case "ghidra_rename_symbol": {
                    Address addr = resolveAddr(prog, getStr(args, "address", ""));
                    String newName = getStr(args, "name", "");
                    if (addr == null) return errorJson("Invalid address");
                    int txn = prog.startTransaction("NexusRE: rename");
                    try {
                        Function func = prog.getFunctionManager().getFunctionAt(addr);
                        if (func != null) {
                            func.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            Symbol sym = prog.getSymbolTable().getPrimarySymbol(addr);
                            if (sym != null) sym.setName(newName, SourceType.USER_DEFINED);
                            else { prog.endTransaction(txn, false); return errorJson("No symbol"); }
                        }
                        prog.endTransaction(txn, true);
                    } catch (Exception e) {
                        prog.endTransaction(txn, false);
                        throw e;
                    }
                    JsonObject r = new JsonObject();
                    r.addProperty("success", true);
                    return r;
                }

                case "ghidra_set_comment": {
                    Address addr = resolveAddr(prog, getStr(args, "address", ""));
                    String comment = getStr(args, "comment", "");
                    boolean rep = args.has("repeatable") && args.get("repeatable").getAsBoolean();
                    if (addr == null) return errorJson("Invalid address");
                    int txn = prog.startTransaction("NexusRE: comment");
                    try {
                        CodeUnit cu = prog.getListing().getCodeUnitAt(addr);
                        if (cu != null) {
                            int ctype = rep ? CodeUnit.REPEATABLE_COMMENT : CodeUnit.EOL_COMMENT;
                            cu.setComment(ctype, comment);
                        }
                        prog.endTransaction(txn, true);
                    } catch (Exception e) {
                        prog.endTransaction(txn, false);
                        throw e;
                    }
                    JsonObject r = new JsonObject();
                    r.addProperty("success", true);
                    return r;
                }

                case "ghidra_patch_bytes": {
                    Address addr = resolveAddr(prog, getStr(args, "address", ""));
                    String hexBytes = getStr(args, "hex_bytes", "");
                    if (addr == null) return errorJson("Invalid address");
                    byte[] raw = hexStringToBytes(hexBytes);
                    int txn = prog.startTransaction("NexusRE: patch");
                    try {
                        prog.getMemory().setBytes(addr, raw);
                        prog.endTransaction(txn, true);
                    } catch (Exception e) {
                        prog.endTransaction(txn, false);
                        throw e;
                    }
                    JsonObject r = new JsonObject();
                    r.addProperty("success", true);
                    return r;
                }

                case "ghidra_scan_aob": {
                    String pattern = getStr(args, "pattern", "");
                    if (pattern.isEmpty()) return errorJson("Pattern required");
                    String[] parts = pattern.trim().split("\\s+");
                    byte[] searchBytes = new byte[parts.length];
                    byte[] maskBytes = new byte[parts.length];
                    for (int i = 0; i < parts.length; i++) {
                        if ("??".equals(parts[i]) || "?".equals(parts[i])) {
                            searchBytes[i] = 0;
                            maskBytes[i] = 0;
                        } else {
                            searchBytes[i] = (byte)(Integer.parseInt(parts[i], 16) & 0xFF);
                            maskBytes[i] = (byte)0xFF;
                        }
                    }
                    Memory mem = prog.getMemory();
                    Address found = mem.findBytes(prog.getMinAddress(), prog.getMaxAddress(),
                        searchBytes, maskBytes, true, new ConsoleTaskMonitor());
                    JsonObject r = new JsonObject();
                    if (found != null) {
                        r.addProperty("address", "0x" + found.toString());
                    } else {
                        r.add("address", JsonNull.INSTANCE);
                    }
                    return r;
                }

                case "ghidra_analyze_functions": {
                    JsonObject r = new JsonObject();
                    r.addProperty("success", true);
                    return r;
                }

                case "ghidra_save_binary": {
                    JsonObject r = new JsonObject();
                    r.addProperty("success", true);
                    r.addProperty("message", "Use File -> Save in Ghidra UI");
                    return r;
                }

                default:
                    return errorJson("Unknown action: " + action);
            }
        }

        // ── Helpers ──
        private Address resolveAddr(Program prog, String addrStr) {
            if (addrStr == null || addrStr.isEmpty()) return null;
            return prog.getAddressFactory().getAddress(addrStr);
        }
        private int getInt(JsonObject o, String k, int def) {
            return o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsInt() : def;
        }
        private String getStr(JsonObject o, String k, String def) {
            return o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsString() : def;
        }
        private JsonObject errorJson(String msg) {
            JsonObject e = new JsonObject();
            e.addProperty("error_message", msg);
            e.addProperty("error_code", "ERROR");
            return e;
        }
        private byte[] hexStringToBytes(String hex) {
            hex = hex.replace(" ", "");
            byte[] b = new byte[hex.length() / 2];
            for (int i = 0; i < b.length; i++) {
                b[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
            }
            return b;
        }
        private void sendJson(HttpExchange ex, int code, JsonObject json) throws IOException {
            byte[] resp = json.toString().getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(code, resp.length);
            ex.getResponseBody().write(resp);
            ex.getResponseBody().close();
        }
    }
}
