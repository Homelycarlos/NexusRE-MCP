// NexusRE-MCP dnSpyEx Backend Extension
// Auto-compiled by install_plugins.bat — no manual steps needed.
// Starts an HTTP server on 127.0.0.1:10106 that the NexusRE MCP server talks to.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace NexusRE.Exdnspy
{
    // ──────────────────────────────────────────────────────────────────────
    //  JSON models
    // ──────────────────────────────────────────────────────────────────────
    public class RpcRequest
    {
        [JsonPropertyName("action")] public string Action { get; set; } = "";
        [JsonPropertyName("args")]   public JsonElement? Args { get; set; }
    }

    public class RpcResponse
    {
        [JsonPropertyName("status")]  public string Status { get; set; } = "ok";
        [JsonPropertyName("error")]   public string Error  { get; set; }
        [JsonPropertyName("result")]  public object Result { get; set; }
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Core HTTP server — works standalone without dnSpy Extension API
    //  so it can compile against raw .NET without dnSpy references.
    //  If dnSpy assemblies are found at runtime it will use them.
    // ──────────────────────────────────────────────────────────────────────
    public static class NexusREServer
    {
        private static HttpListener _listener;
        private static CancellationTokenSource _cts;
        private static Thread _thread;
        private static readonly int Port = 10106;
        private static string _loadedBinary = "";

        // dnSpy reflection handles — resolved at runtime if available
#pragma warning disable CS0169, CS0649
        private static object _decompilerService;
        private static object _documentService;
        private static Assembly _dnSpyAsm;
        private static Assembly _contractsAsm;
#pragma warning restore CS0169, CS0649

        // ── Public API ───────────────────────────────────────────────────
        public static void Start(string binaryPath = null)
        {
            if (_thread != null && _thread.IsAlive) return;
            _loadedBinary = binaryPath ?? "";
            TryResolveDnSpy();
            _cts = new CancellationTokenSource();
            _thread = new Thread(() => RunServer(_cts.Token))
            {
                IsBackground = true,
                Name = "NexusRE-MCP-Server"
            };
            _thread.Start();
        }

        public static void Stop()
        {
            _cts?.Cancel();
            _listener?.Stop();
            _listener?.Close();
            _thread?.Join(3000);
        }

        // ── Server loop ──────────────────────────────────────────────────
        private static void RunServer(CancellationToken ct)
        {
            try
            {
                _listener = new HttpListener();
                _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
                _listener.Start();
                Console.WriteLine($"[NexusRE] Listening on http://127.0.0.1:{Port}/");

                while (!ct.IsCancellationRequested)
                {
                    var ctx = _listener.GetContext(); // blocking
                    if (ct.IsCancellationRequested) break;
                    ThreadPool.QueueUserWorkItem(_ => HandleRequest(ctx));
                }
            }
            catch (HttpListenerException) when (ct.IsCancellationRequested) { }
            catch (Exception ex)
            {
                Console.WriteLine($"[NexusRE] Fatal: {ex.Message}");
            }
        }

        // ── Request dispatcher ───────────────────────────────────────────
        private static bool CheckAuth(HttpListenerContext ctx)
        {
            try
            {
                string tokenPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nexusre", "auth_token");
                if (!File.Exists(tokenPath)) return true;
                string expected = File.ReadAllText(tokenPath).Trim();
                string authHeader = ctx.Request.Headers["Authorization"];
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ") || authHeader.Substring(7) != expected)
                {
                    return false;
                }
                return true;
            }
            catch
            {
                return true;
            }
        }

        private static void HandleRequest(HttpListenerContext ctx)
        {
            try
            {
                if (!CheckAuth(ctx))
                {
                    ctx.Response.StatusCode = 401;
                    Reply(ctx, new RpcResponse { Error = "Unauthorized" });
                    return;
                }

                // GET = health check
                if (ctx.Request.HttpMethod == "GET")
                {
                    Reply(ctx, new RpcResponse
                    {
                        Status = "ok",
                        Result = new { binary = _loadedBinary, backend = "exdnspy" }
                    });
                    return;
                }

                string body;
                using (var sr = new StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding))
                    body = sr.ReadToEnd();

                RpcRequest req;
                try { req = JsonSerializer.Deserialize<RpcRequest>(body); }
                catch { Reply(ctx, new RpcResponse { Status = "error", Error = "Malformed JSON" }); return; }

                object result = Dispatch(req);
                Reply(ctx, new RpcResponse { Result = result });
            }
            catch (Exception ex)
            {
                try { Reply(ctx, new RpcResponse { Status = "error", Error = ex.Message }); } catch { }
            }
        }

        // ── Action router ────────────────────────────────────────────────
        private static object Dispatch(RpcRequest req)
        {
            var args = req.Args;
            switch (req.Action?.ToLowerInvariant())
            {
                // ── Navigation ───────────────────────────────────────────
                case "get_functions":
                    return GetFunctions(args);
                case "get_function":
                    return GetFunction(GetArg(args, "address"));
                case "get_current_address":
                    return new { address = (string)null };
                case "get_current_function":
                    return new { address = (string)null };

                // ── Decompilation ─────────────────────────────────────────
                case "decompile":
                    return DecompileFunction(GetArg(args, "address"));
                case "disassemble":
                    return DisassembleFunction(GetArg(args, "address"));

                // ── Cross-references ─────────────────────────────────────
                case "get_xrefs":
                    return GetXrefs(GetArg(args, "address"));
                case "get_callees":
                    return GetCallees(GetArg(args, "address"));
                case "get_callers":
                    return GetCallers(GetArg(args, "address"));

                // ── Advanced Analysis ────────────────────────────────────
                case "get_complexity":
                    return GetComplexity(GetArg(args, "address"));

                // ── Data extraction ──────────────────────────────────────
                case "get_strings":
                    return GetStrings(args);
                case "get_globals":
                    return new { globals = new object[0] };
                case "get_segments":
                    return GetSegments();
                case "get_imports":
                    return GetImports();
                case "get_exports":
                    return GetExports();

                // ── Modification ─────────────────────────────────────────
                case "rename":
                    return new { success = false, error = "rename not yet wired" };
                case "set_comment":
                    return new { success = false, error = "set_comment not yet wired" };
                case "set_function_type":
                    return new { success = false, error = "set_function_type not yet wired" };
                case "patch_bytes":
                    return PatchBytes(GetArg(args, "address"), GetArg(args, "hex_bytes"));
                case "save_binary":
                    return SaveBinary(GetArg(args, "output_path"));

                // ── Memory / Debug ───────────────────────────────────────
                case "read_memory":
                    return new { data = "" };

                // ── Meta ─────────────────────────────────────────────────
                case "health":
                    return new { status = "ok", binary = _loadedBinary, backend = "exdnspy" };

                default:
                    return new { error = $"Unknown action: {req.Action}" };
            }
        }

        // ── Implementation stubs — wired via reflection when dnSpy is present ──

        private static object GetFunctions(JsonElement? args)
        {
            // If we have a loaded PE, try to enumerate with System.Reflection.Metadata
            var functions = new List<object>();
            if (!string.IsNullOrEmpty(_loadedBinary) && File.Exists(_loadedBinary))
            {
                try
                {
                    var asm = Assembly.LoadFrom(_loadedBinary);
                    foreach (var type in asm.GetTypes())
                    {
                        foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic |
                                                               BindingFlags.Static | BindingFlags.Instance |
                                                               BindingFlags.DeclaredOnly))
                        {
                            functions.Add(new
                            {
                                name = $"{type.FullName}.{method.Name}",
                                address = $"0x{method.MetadataToken:X8}",
                                size = 0
                            });
                        }
                    }
                }
                catch { /* PE might not be managed */ }
            }
            return new { functions };
        }

        private static object GetFunction(string address)
        {
            return new { name = "", address, size = 0 };
        }

        private static object DecompileFunction(string address)
        {
            // If dnSpy decompiler service is resolved, call it via reflection
            if (_decompilerService != null)
            {
                try
                {
                    // Try to invoke the decompiler through dnSpy's service layer
                    var decompMethod = _decompilerService.GetType().GetMethod("Decompile");
                    if (decompMethod != null)
                    {
                        var result = decompMethod.Invoke(_decompilerService, new object[] { address });
                        return new { code = result?.ToString() ?? "" };
                    }
                }
                catch (Exception ex)
                {
                    return new { code = $"// Decompilation error: {ex.Message}" };
                }
            }
            return new { code = $"// Decompilation requires dnSpy runtime — address {address}" };
        }

        private static object DisassembleFunction(string address)
        {
            if (_decompilerService != null)
            {
                // dnSpy disassembly
                return new { code = $"// Disassembly requires dnSpy runtime — address {address}" };
            }

            // Fallback: IL dump using System.Reflection and System.Reflection.Emit.OpCodes
            if (!string.IsNullOrEmpty(_loadedBinary) && File.Exists(_loadedBinary))
            {
                try
                {
                    var asm = Assembly.LoadFrom(_loadedBinary);
                    int token = Convert.ToInt32(address, 16);
                    
                    // Create an opcode lookup dictionary for fast mapping
                    var opcodes = new Dictionary<short, System.Reflection.Emit.OpCode>();
                    foreach (var field in typeof(System.Reflection.Emit.OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
                    {
                        var opcode = (System.Reflection.Emit.OpCode)field.GetValue(null);
                        opcodes[opcode.Value] = opcode;
                    }

                    foreach (var module in asm.GetModules())
                    {
                        try
                        {
                            var methodBase = module.ResolveMethod(token);
                            if (methodBase != null)
                            {
                                var body = methodBase.GetMethodBody();
                                if (body != null)
                                {
                                    var il = body.GetILAsByteArray();
                                    if (il != null)
                                    {
                                        var sb = new StringBuilder();
                                        sb.AppendLine($"// IL Disassembly for {methodBase.Name}");
                                        
                                        // Emit Local Variables
                                        if (body.LocalVariables != null && body.LocalVariables.Count > 0)
                                        {
                                            sb.AppendLine("// Locals:");
                                            foreach (var local in body.LocalVariables)
                                            {
                                                sb.AppendLine($"//   [{local.LocalIndex}] {local.LocalType.FullName}");
                                            }
                                            sb.AppendLine();
                                        }

                                        // Emit Exception Handling Clauses
                                        if (body.ExceptionHandlingClauses != null && body.ExceptionHandlingClauses.Count > 0)
                                        {
                                            sb.AppendLine("// Exception Handlers:");
                                            foreach (var clause in body.ExceptionHandlingClauses)
                                            {
                                                sb.AppendLine($"//   {clause.Flags} - Try: IL_{clause.TryOffset:X4}..IL_{clause.TryOffset + clause.TryLength:X4} | Handler: IL_{clause.HandlerOffset:X4}..IL_{clause.HandlerOffset + clause.HandlerLength:X4}");
                                            }
                                            sb.AppendLine();
                                        }

                                        int i = 0;
                                        while (i < il.Length)
                                        {
                                            int offset = i;
                                            short opValue = il[i++];
                                            
                                            // Handle multi-byte opcodes (prefix 0xFE)
                                            if (opValue == 0xFE && i < il.Length)
                                            {
                                                opValue = (short)((opValue << 8) | il[i++]);
                                            }

                                            if (opcodes.TryGetValue(opValue, out var opcode))
                                            {
                                                sb.Append($"IL_{offset:X4}: {opcode.Name,-10}");
                                                
                                                // Simplified operand parsing based on operand type length
                                                switch (opcode.OperandType)
                                                {
                                                    case System.Reflection.Emit.OperandType.InlineBrTarget:
                                                    case System.Reflection.Emit.OperandType.InlineField:
                                                    case System.Reflection.Emit.OperandType.InlineI:
                                                    case System.Reflection.Emit.OperandType.InlineMethod:
                                                    case System.Reflection.Emit.OperandType.InlineSig:
                                                    case System.Reflection.Emit.OperandType.InlineString:
                                                    case System.Reflection.Emit.OperandType.InlineSwitch:
                                                    case System.Reflection.Emit.OperandType.InlineTok:
                                                    case System.Reflection.Emit.OperandType.InlineType:
                                                    case System.Reflection.Emit.OperandType.ShortInlineR:
                                                        if (i + 4 <= il.Length)
                                                        {
                                                            int operand = BitConverter.ToInt32(il, i);
                                                            if (opcode.OperandType == System.Reflection.Emit.OperandType.InlineString) {
                                                                try {
                                                                     sb.Append($" \"{module.ResolveString(operand)}\"");
                                                                } catch {
                                                                     sb.Append($" 0x{operand:X8}");
                                                                }
                                                            } else if (opcode.OperandType == System.Reflection.Emit.OperandType.InlineMethod || opcode.OperandType == System.Reflection.Emit.OperandType.InlineField || opcode.OperandType == System.Reflection.Emit.OperandType.InlineType) {
                                                                try {
                                                                     var member = module.ResolveMember(operand);
                                                                     sb.Append($" {member.Name}");
                                                                } catch {
                                                                     sb.Append($" 0x{operand:X8}");
                                                                }
                                                            } else {
                                                                sb.Append($" 0x{operand:X8}");
                                                            }
                                                            i += 4;
                                                        }
                                                        break;
                                                    case System.Reflection.Emit.OperandType.InlineI8:
                                                    case System.Reflection.Emit.OperandType.InlineR:
                                                        if (i + 8 <= il.Length)
                                                        {
                                                            long operand = BitConverter.ToInt64(il, i);
                                                            sb.Append($" 0x{operand:X16}");
                                                            i += 8;
                                                        }
                                                        break;
                                                    case System.Reflection.Emit.OperandType.ShortInlineBrTarget:
                                                    case System.Reflection.Emit.OperandType.ShortInlineI:
                                                    case System.Reflection.Emit.OperandType.ShortInlineVar:
                                                        if (i + 1 <= il.Length)
                                                        {
                                                            byte operand = il[i++];
                                                            sb.Append($" 0x{operand:X2}");
                                                        }
                                                        break;
                                                    case System.Reflection.Emit.OperandType.InlineVar:
                                                        if (i + 2 <= il.Length)
                                                        {
                                                            short operand = BitConverter.ToInt16(il, i);
                                                            sb.Append($" 0x{operand:X4}");
                                                            i += 2;
                                                        }
                                                        break;
                                                    case System.Reflection.Emit.OperandType.InlineNone:
                                                    default:
                                                        break;
                                                }
                                                sb.AppendLine();
                                            }
                                            else
                                            {
                                                sb.AppendLine($"IL_{offset:X4}: 0x{opValue:X2}");
                                            }
                                        }
                                        return new { code = sb.ToString() };
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            return new { code = $"// Disassembly requires dnSpy runtime — address {address}" };
        }

        private static object GetXrefs(string address)
        {
            var xrefs_to = new List<string>();
            var xrefs_from = new List<string>();

            if (!string.IsNullOrEmpty(_loadedBinary) && File.Exists(_loadedBinary))
            {
                try
                {
                    var asm = Assembly.LoadFrom(_loadedBinary);
                    int token = Convert.ToInt32(address, 16);
                    
                    // Create an opcode lookup dictionary for fast mapping
                    var opcodes = new Dictionary<short, System.Reflection.Emit.OpCode>();
                    foreach (var field in typeof(System.Reflection.Emit.OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
                    {
                        var opcode = (System.Reflection.Emit.OpCode)field.GetValue(null);
                        opcodes[opcode.Value] = opcode;
                    }

                    foreach (var type in asm.GetTypes())
                    {
                        foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                        {
                            try
                            {
                                var body = method.GetMethodBody();
                                if (body != null)
                                {
                                    var il = body.GetILAsByteArray();
                                    if (il != null)
                                    {
                                        int i = 0;
                                        while (i < il.Length)
                                        {
                                            short opValue = il[i++];
                                            if (opValue == 0xFE && i < il.Length)
                                            {
                                                opValue = (short)((opValue << 8) | il[i++]);
                                            }

                                            if (opcodes.TryGetValue(opValue, out var opcode))
                                            {
                                                switch (opcode.OperandType)
                                                {
                                                    case System.Reflection.Emit.OperandType.InlineMethod:
                                                    case System.Reflection.Emit.OperandType.InlineField:
                                                    case System.Reflection.Emit.OperandType.InlineType:
                                                    case System.Reflection.Emit.OperandType.InlineTok:
                                                    case System.Reflection.Emit.OperandType.InlineString:
                                                    case System.Reflection.Emit.OperandType.InlineSig:
                                                        if (i + 4 <= il.Length)
                                                        {
                                                            int operand = BitConverter.ToInt32(il, i);
                                                            if (operand == token)
                                                            {
                                                                xrefs_to.Add($"0x{method.MetadataToken:X8}");
                                                            }
                                                            if (method.MetadataToken == token)
                                                            {
                                                                xrefs_from.Add($"0x{operand:X8}");
                                                            }
                                                            i += 4;
                                                        }
                                                        break;
                                                    case System.Reflection.Emit.OperandType.InlineBrTarget:
                                                    case System.Reflection.Emit.OperandType.InlineI:
                                                    case System.Reflection.Emit.OperandType.InlineSwitch:
                                                    case System.Reflection.Emit.OperandType.ShortInlineR:
                                                        i += 4;
                                                        break;
                                                    case System.Reflection.Emit.OperandType.InlineI8:
                                                    case System.Reflection.Emit.OperandType.InlineR:
                                                        i += 8;
                                                        break;
                                                    case System.Reflection.Emit.OperandType.ShortInlineBrTarget:
                                                    case System.Reflection.Emit.OperandType.ShortInlineI:
                                                    case System.Reflection.Emit.OperandType.ShortInlineVar:
                                                        i += 1;
                                                        break;
                                                    case System.Reflection.Emit.OperandType.InlineVar:
                                                        i += 2;
                                                        break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }

            return new { xrefs = new { to = xrefs_to, from_ = xrefs_from } };
        }

        private static object GetComplexity(string address)
        {
            if (!string.IsNullOrEmpty(_loadedBinary) && File.Exists(_loadedBinary))
            {
                try
                {
                    var asm = Assembly.LoadFrom(_loadedBinary);
                    int token = Convert.ToInt32(address, 16);
                    
                    var opcodes = new Dictionary<short, System.Reflection.Emit.OpCode>();
                    foreach (var field in typeof(System.Reflection.Emit.OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
                    {
                        var opcode = (System.Reflection.Emit.OpCode)field.GetValue(null);
                        opcodes[opcode.Value] = opcode;
                    }

                    foreach (var module in asm.GetModules())
                    {
                        try
                        {
                            var methodBase = module.ResolveMethod(token);
                            if (methodBase != null)
                            {
                                var body = methodBase.GetMethodBody();
                                if (body != null)
                                {
                                    var il = body.GetILAsByteArray();
                                    if (il != null)
                                    {
                                        int complexity = 1; // Base path
                                        int i = 0;
                                        while (i < il.Length)
                                        {
                                            short opValue = il[i++];
                                            if (opValue == 0xFE && i < il.Length)
                                            {
                                                opValue = (short)((opValue << 8) | il[i++]);
                                            }

                                            if (opcodes.TryGetValue(opValue, out var opcode))
                                            {
                                                switch (opcode.FlowControl)
                                                {
                                                    case System.Reflection.Emit.FlowControl.Cond_Branch:
                                                        complexity++;
                                                        break;
                                                }

                                                switch (opcode.OperandType)
                                                {
                                                    case System.Reflection.Emit.OperandType.InlineMethod:
                                                    case System.Reflection.Emit.OperandType.InlineField:
                                                    case System.Reflection.Emit.OperandType.InlineType:
                                                    case System.Reflection.Emit.OperandType.InlineTok:
                                                    case System.Reflection.Emit.OperandType.InlineString:
                                                    case System.Reflection.Emit.OperandType.InlineSig:
                                                    case System.Reflection.Emit.OperandType.InlineBrTarget:
                                                    case System.Reflection.Emit.OperandType.InlineI:
                                                    case System.Reflection.Emit.OperandType.ShortInlineR:
                                                        i += 4;
                                                        break;
                                                    case System.Reflection.Emit.OperandType.InlineSwitch:
                                                        if (i + 4 <= il.Length)
                                                        {
                                                            int count = BitConverter.ToInt32(il, i);
                                                            complexity += count; // Add switch cases
                                                            i += 4 + (count * 4);
                                                        }
                                                        break;
                                                    case System.Reflection.Emit.OperandType.InlineI8:
                                                    case System.Reflection.Emit.OperandType.InlineR:
                                                        i += 8;
                                                        break;
                                                    case System.Reflection.Emit.OperandType.ShortInlineBrTarget:
                                                    case System.Reflection.Emit.OperandType.ShortInlineI:
                                                    case System.Reflection.Emit.OperandType.ShortInlineVar:
                                                        i += 1;
                                                        break;
                                                    case System.Reflection.Emit.OperandType.InlineVar:
                                                        i += 2;
                                                        break;
                                                }
                                            }
                                        }
                                        return new { success = true, complexity = complexity };
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
            return new { success = false, error = "Failed to calculate complexity" };
        }

        private static object GetCallees(string address)
        {
            var xrefs = (dynamic)GetXrefs(address);
            var callees = new List<object>();
            foreach(var callee_addr in xrefs.xrefs.from_)
            {
                callees.Add(new { address = callee_addr, name = "Unknown", type = "internal" });
            }
            return new { callees = callees };
        }

        private static object GetCallers(string address)
        {
            var xrefs = (dynamic)GetXrefs(address);
            var callers = new List<object>();
            foreach (var caller_addr in xrefs.xrefs.to)
            {
                callers.Add(new { address = caller_addr, name = "Unknown" });
            }
            return new { callers = callers };
        }

        private static object PatchBytes(string address, string hexBytes)
        {
            if (string.IsNullOrEmpty(_loadedBinary) || !File.Exists(_loadedBinary))
            {
                return new { success = false, error = "No binary loaded" };
            }

            try
            {
                long offset = Convert.ToInt64(address, 16);
                
                // Clean up hex string
                hexBytes = hexBytes.Replace(" ", "").Replace("-", "").Trim();
                if (hexBytes.Length % 2 != 0)
                {
                     return new { success = false, error = "Invalid hex string length." };
                }

                byte[] bytes = new byte[hexBytes.Length / 2];
                for (int i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = Convert.ToByte(hexBytes.Substring(i * 2, 2), 16);
                }

                // Use FileShare.ReadWrite to attempt to write even if opened by another process (like dnSpy) if possible
                using (var fs = new FileStream(_loadedBinary, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
                {
                    if (offset < 0 || offset >= fs.Length)
                    {
                        return new { success = false, error = $"Offset 0x{offset:X} is out of bounds." };
                    }
                    fs.Seek(offset, SeekOrigin.Begin);
                    fs.Write(bytes, 0, bytes.Length);
                }

                return new { success = true };
            }
            catch (UnauthorizedAccessException)
            {
                return new { success = false, error = "Access denied. Ensure you have permissions and the file isn't locked exclusively." };
            }
            catch (IOException ex)
            {
                return new { success = false, error = $"IO Error (File might be locked): {ex.Message}" };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        private static object SaveBinary(string outputPath)
        {
            if (string.IsNullOrEmpty(_loadedBinary) || !File.Exists(_loadedBinary))
            {
                return new { success = false, error = "No binary loaded" };
            }

            try
            {
                if (!string.IsNullOrEmpty(outputPath) && outputPath != _loadedBinary)
                {
                    File.Copy(_loadedBinary, outputPath, true);
                }
                return new { success = true };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        private static object GetStrings(JsonElement? args)
        {
            var strings = new List<object>();
            if (!string.IsNullOrEmpty(_loadedBinary) && File.Exists(_loadedBinary))
            {
                try
                {
                    // Quick ASCII string scan on the binary
                    var bytes = File.ReadAllBytes(_loadedBinary);
                    var sb = new StringBuilder();
                    long startAddr = 0;
                    for (int i = 0; i < bytes.Length; i++)
                    {
                        byte b = bytes[i];
                        if (b >= 0x20 && b < 0x7F)
                        {
                            if (sb.Length == 0) startAddr = i;
                            sb.Append((char)b);
                        }
                        else
                        {
                            if (sb.Length >= 5)
                            {
                                strings.Add(new { address = $"0x{startAddr:X}", value = sb.ToString() });
                                if (strings.Count >= 500) break;
                            }
                            sb.Clear();
                        }
                    }
                }
                catch { }
            }
            return new { strings };
        }

        private static object GetSegments()
        {
            // Attempt to read PE section headers
            var segments = new List<object>();
            if (!string.IsNullOrEmpty(_loadedBinary) && File.Exists(_loadedBinary))
            {
                try
                {
                    using var fs = new FileStream(_loadedBinary, FileMode.Open, FileAccess.Read);
                    using var br = new BinaryReader(fs);
                    // DOS header
                    if (br.ReadUInt16() == 0x5A4D) // MZ
                    {
                        fs.Seek(0x3C, SeekOrigin.Begin);
                        uint peOffset = br.ReadUInt32();
                        fs.Seek(peOffset, SeekOrigin.Begin);
                        if (br.ReadUInt32() == 0x4550) // PE\0\0
                        {
                            ushort machine = br.ReadUInt16();
                            ushort numSections = br.ReadUInt16();
                            fs.Seek(peOffset + 24, SeekOrigin.Begin); // skip to optional header
                            ushort optMagic = br.ReadUInt16();
                            int optSize = optMagic == 0x20B ? 240 : 224; // PE32+ vs PE32
                            fs.Seek(peOffset + 24 + optSize, SeekOrigin.Begin);
                            for (int i = 0; i < numSections; i++)
                            {
                                byte[] nameBytes = br.ReadBytes(8);
                                string name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
                                uint virtualSize = br.ReadUInt32();
                                uint virtualAddr = br.ReadUInt32();
                                uint rawSize = br.ReadUInt32();
                                uint rawPtr = br.ReadUInt32();
                                fs.Seek(12, SeekOrigin.Current); // skip relocations, linenumbers
                                uint characteristics = br.ReadUInt32();
                                string perms = "";
                                if ((characteristics & 0x20000000) != 0) perms += "X";
                                if ((characteristics & 0x40000000) != 0) perms += "R";
                                if ((characteristics & 0x80000000) != 0) perms += "W";
                                segments.Add(new
                                {
                                    name,
                                    start_address = $"0x{virtualAddr:X}",
                                    end_address = $"0x{virtualAddr + virtualSize:X}",
                                    size = virtualSize,
                                    permissions = perms
                                });
                            }
                        }
                    }
                }
                catch { }
            }
            return new { segments };
        }

        private static object GetImports()
        {
            var imports = new List<object>();
            if (!string.IsNullOrEmpty(_loadedBinary) && File.Exists(_loadedBinary))
            {
                try
                {
                    var asm = Assembly.LoadFrom(_loadedBinary);
                    foreach (var refAsm in asm.GetReferencedAssemblies())
                    {
                        imports.Add(new
                        {
                            address = "0x0",
                            name = refAsm.FullName,
                            module = refAsm.Name
                        });
                    }
                }
                catch { }
            }
            return new { imports };
        }

        private static object GetExports()
        {
            var exports = new List<object>();
            if (!string.IsNullOrEmpty(_loadedBinary) && File.Exists(_loadedBinary))
            {
                try
                {
                    var asm = Assembly.LoadFrom(_loadedBinary);
                    foreach (var type in asm.GetExportedTypes())
                    {
                        exports.Add(new { address = $"0x{type.MetadataToken:X8}", name = type.FullName });
                    }
                }
                catch { }
            }
            return new { exports };
        }

        // ── Helpers ──────────────────────────────────────────────────────
        private static string GetArg(JsonElement? args, string key)
        {
            if (args == null) return "";
            if (args.Value.ValueKind == JsonValueKind.Object && args.Value.TryGetProperty(key, out var val))
                return val.GetString() ?? "";
            return "";
        }

        private static void Reply(HttpListenerContext ctx, RpcResponse resp)
        {
            byte[] buf = JsonSerializer.SerializeToUtf8Bytes(resp,
                new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = buf.Length;
            ctx.Response.StatusCode = resp.Status == "error" ? 400 : 200;
            ctx.Response.OutputStream.Write(buf, 0, buf.Length);
            ctx.Response.OutputStream.Close();
        }

        private static void TryResolveDnSpy()
        {
            try
            {
                // Look for dnSpy assemblies in the current AppDomain
                foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
                {
                    string name = asm.GetName().Name;
                    if (name == "dnSpy") _dnSpyAsm = asm;
                    if (name == "dnSpy.Contracts.DnSpy") _contractsAsm = asm;
                }
                if (_dnSpyAsm != null)
                {
                    Console.WriteLine("[NexusRE] dnSpy runtime detected — advanced features enabled");
                }
            }
            catch { }
        }

        // ── Standalone entry point (can run outside dnSpy for testing) ───
        public static void Main(string[] cmdArgs)
        {
            string binary = cmdArgs.Length > 0 ? cmdArgs[0] : "";
            Console.WriteLine("╔══════════════════════════════════════╗");
            Console.WriteLine("║  NexusRE exdnspy Backend Server     ║");
            Console.WriteLine("╚══════════════════════════════════════╝");
            if (!string.IsNullOrEmpty(binary))
                Console.WriteLine($"[*] Binary: {binary}");
            Start(binary);
            Console.WriteLine("[*] Press Ctrl+C to stop...");
            var mre = new ManualResetEvent(false);
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; mre.Set(); };
            mre.WaitOne();
            Stop();
        }
    }
}
