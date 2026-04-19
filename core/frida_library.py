"""
NexusRE Frida Snippet Library

Pre-built Frida hook templates the AI can deploy instantly.
Snippets are stored in the brain DB for reuse across sessions.
"""
import sqlite3
import json
import logging

logger = logging.getLogger("NexusRE")

# ── Built-in Snippet Templates ─────────────────────────────────────────────

BUILTIN_SNIPPETS = {
    "function_hooker": {
        "description": "Hook a function and log all calls with arguments and return value",
        "template": '''
Interceptor.attach(ptr("{address}"), {{
    onEnter: function(args) {{
        console.log("[HOOK] {func_name} called");
        console.log("  arg0: " + args[0]);
        console.log("  arg1: " + args[1]);
        console.log("  arg2: " + args[2]);
        console.log("  arg3: " + args[3]);
    }},
    onLeave: function(retval) {{
        console.log("  retval: " + retval);
    }}
}});
''',
        "params": ["address", "func_name"]
    },
    "return_spoofer": {
        "description": "Replace a function's return value with a custom value",
        "template": '''
Interceptor.attach(ptr("{address}"), {{
    onLeave: function(retval) {{
        console.log("[SPOOF] {func_name} original return: " + retval);
        retval.replace(ptr({spoof_value}));
        console.log("[SPOOF] Replaced with: {spoof_value}");
    }}
}});
''',
        "params": ["address", "func_name", "spoof_value"]
    },
    "argument_logger": {
        "description": "Log all arguments passed to a function (up to 8 args)",
        "template": '''
Interceptor.attach(ptr("{address}"), {{
    onEnter: function(args) {{
        console.log("\\n[ARGS] {func_name} @ " + this.context.pc);
        for (var i = 0; i < {arg_count}; i++) {{
            try {{
                console.log("  arg" + i + ": " + args[i] + " (" + args[i].readUtf8String() + ")");
            }} catch(e) {{
                console.log("  arg" + i + ": " + args[i]);
            }}
        }}
    }}
}});
''',
        "params": ["address", "func_name", "arg_count"]
    },
    "memory_read_watcher": {
        "description": "Watch reads from a specific memory address",
        "template": '''
MemoryAccessMonitor.enable({{ base: ptr("{address}"), size: {size} }}, {{
    onAccess: function(details) {{
        console.log("[WATCH] " + details.operation + " at " + details.address +
                    " from " + details.from + " (thread " + details.threadId + ")");
    }}
}});
''',
        "params": ["address", "size"]
    },
    "module_export_scanner": {
        "description": "Enumerate all exports from a module",
        "template": '''
var mod = Process.findModuleByName("{module_name}");
if (mod) {{
    console.log("[MODULE] " + mod.name + " base: " + mod.base + " size: " + mod.size);
    mod.enumerateExports().forEach(function(exp) {{
        console.log("  " + exp.type + " " + exp.name + " @ " + exp.address);
    }});
}} else {{
    console.log("[ERROR] Module {module_name} not found");
}}
''',
        "params": ["module_name"]
    },
    "anti_debug_bypass": {
        "description": "Bypass common anti-debugging checks (IsDebuggerPresent, NtQueryInformationProcess)",
        "template": '''
// Bypass IsDebuggerPresent
var isDbg = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
if (isDbg) {{
    Interceptor.replace(isDbg, new NativeCallback(function() {{
        return 0;
    }}, 'int', []));
    console.log("[BYPASS] IsDebuggerPresent hooked -> always returns 0");
}}

// Bypass CheckRemoteDebuggerPresent
var checkRemote = Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent");
if (checkRemote) {{
    Interceptor.attach(checkRemote, {{
        onLeave: function(retval) {{
            // Set the output bool to FALSE
            this.context.rdx.writeU32(0);
        }}
    }});
    console.log("[BYPASS] CheckRemoteDebuggerPresent hooked");
}}
''',
        "params": []
    },
    "string_tracer": {
        "description": "Trace all calls to string functions and log the strings being processed",
        "template": '''
["strlen", "strcmp", "strstr", "strcpy", "wcslen", "wcscmp"].forEach(function(fname) {{
    var addr = Module.findExportByName(null, fname);
    if (addr) {{
        Interceptor.attach(addr, {{
            onEnter: function(args) {{
                try {{
                    var s = args[0].readUtf8String();
                    if (s && s.length > 2 && s.length < 256) {{
                        console.log("[STR] " + fname + ": " + s);
                    }}
                }} catch(e) {{}}
            }}
        }});
    }}
}});
console.log("[TRACE] String function hooks installed");
''',
        "params": []
    }
}


class FridaLibrary:
    def __init__(self, db_path="nexusre_brain.db"):
        self.db_path = db_path
        self._init_table()

    def _init_table(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS frida_snippets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        description TEXT,
                        template TEXT NOT NULL,
                        params_json TEXT,
                        category TEXT DEFAULT 'custom',
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"FridaLibrary init error: {e}")

    def save_snippet(self, name: str, description: str, template: str,
                     params: list = None, category: str = "custom") -> bool:
        """Save a custom Frida snippet to the library."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO frida_snippets
                    (name, description, template, params_json, category)
                    VALUES (?, ?, ?, ?, ?)
                """, (name, description, template, json.dumps(params or []), category))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Save snippet error: {e}")
            return False

    def get_snippet(self, name: str) -> dict:
        """Get a snippet by name (checks builtins first, then DB)."""
        if name in BUILTIN_SNIPPETS:
            return {"name": name, **BUILTIN_SNIPPETS[name], "source": "builtin"}
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT name, description, template, params_json FROM frida_snippets WHERE name = ?",
                    (name,)
                ).fetchone()
                if row:
                    return {
                        "name": row[0], "description": row[1],
                        "template": row[2], "params": json.loads(row[3]),
                        "source": "custom"
                    }
        except Exception as e:
            logger.error(f"Get snippet error: {e}")
        return None

    def list_snippets(self) -> list:
        """List all available snippets (builtins + custom)."""
        snippets = []
        for name, data in BUILTIN_SNIPPETS.items():
            snippets.append({
                "name": name,
                "description": data["description"],
                "params": data["params"],
                "source": "builtin"
            })
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT name, description, params_json, category FROM frida_snippets"
                ).fetchall()
                for row in rows:
                    snippets.append({
                        "name": row[0], "description": row[1],
                        "params": json.loads(row[2]), "source": "custom",
                        "category": row[3]
                    })
        except Exception:
            pass
        return snippets

    def render_snippet(self, name: str, params: dict) -> str:
        """Render a snippet template with the given parameters."""
        snippet = self.get_snippet(name)
        if not snippet:
            return None
        try:
            return snippet["template"].format(**params)
        except KeyError as e:
            return f"// Missing parameter: {e}"


frida_library = FridaLibrary()
