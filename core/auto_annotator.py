"""
NexusRE Auto-Annotator

Known pattern library for automatic function identification.
Contains fingerprints for common crypto, networking, anti-cheat, and
game engine patterns. When running auto_annotate, decompiled functions
are matched against these patterns and auto-labeled.
"""
import re
import logging

logger = logging.getLogger("NexusRE")

# ── Known Pattern Library ──────────────────────────────────────────────────────
# Each pattern has: keywords (in decompiled code), imports/calls, and a label.

KNOWN_PATTERNS = [
    # ── Cryptography ──
    {
        "label": "AES_Encrypt",
        "category": "crypto",
        "keywords": ["SubBytes", "ShiftRows", "MixColumns", "AddRoundKey", "Rijndael"],
        "calls": ["aes_encrypt", "AES_cbc_encrypt", "EVP_EncryptUpdate"],
        "min_score": 2
    },
    {
        "label": "AES_Decrypt",
        "category": "crypto",
        "keywords": ["InvSubBytes", "InvShiftRows", "InvMixColumns", "AddRoundKey"],
        "calls": ["aes_decrypt", "AES_cbc_decrypt", "EVP_DecryptUpdate"],
        "min_score": 2
    },
    {
        "label": "RC4_Crypt",
        "category": "crypto",
        "keywords": ["swap", "256", "mod"],
        "calls": ["RC4", "rc4_crypt"],
        "regex": r'(\w+)\s*=\s*\(\s*\1\s*\+\s*\w+\[.*?\]\s*\)\s*&\s*0xff',
        "min_score": 2
    },
    {
        "label": "MD5_Transform",
        "category": "crypto",
        "keywords": ["0x67452301", "0xefcdab89", "0x98badcfe", "0x10325476"],
        "calls": ["MD5_Init", "MD5_Update", "MD5_Final"],
        "min_score": 1
    },
    {
        "label": "SHA256_Transform",
        "category": "crypto",
        "keywords": ["0x6a09e667", "0xbb67ae85", "0x3c6ef372", "0xa54ff53a"],
        "calls": ["SHA256_Init", "SHA256_Update"],
        "min_score": 1
    },
    {
        "label": "XOR_Decrypt",
        "category": "crypto",
        "keywords": ["^=", "xor"],
        "regex": r'for\s*\(.*\)\s*\{[^}]*\^=',
        "min_score": 2
    },
    {
        "label": "Base64_Encode",
        "category": "crypto",
        "keywords": ["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"],
        "calls": ["base64_encode", "b64_encode"],
        "min_score": 1
    },

    # ── Networking ──
    {
        "label": "Socket_Connect",
        "category": "network",
        "keywords": ["AF_INET", "SOCK_STREAM", "sockaddr_in", "htons"],
        "calls": ["socket", "connect", "WSAStartup"],
        "min_score": 2
    },
    {
        "label": "HTTP_Request",
        "category": "network",
        "keywords": ["GET ", "POST ", "HTTP/1", "Content-Type", "User-Agent"],
        "calls": ["HttpOpenRequest", "InternetConnect", "WinHttpOpen", "curl_easy"],
        "min_score": 2
    },
    {
        "label": "DNS_Resolve",
        "category": "network",
        "keywords": ["getaddrinfo", "gethostbyname", "DNS"],
        "calls": ["getaddrinfo", "gethostbyname", "DnsQuery"],
        "min_score": 1
    },
    {
        "label": "Send_Recv_Data",
        "category": "network",
        "keywords": ["SOCK_STREAM", "recv", "send"],
        "calls": ["send", "recv", "sendto", "recvfrom", "WSASend", "WSARecv"],
        "min_score": 2
    },

    # ── Anti-Cheat / Anti-Debug ──
    {
        "label": "AntiDebug_IsDebuggerPresent",
        "category": "anticheat",
        "keywords": ["PEB", "BeingDebugged", "IsDebuggerPresent"],
        "calls": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"],
        "min_score": 1
    },
    {
        "label": "AntiDebug_TimingCheck",
        "category": "anticheat",
        "keywords": ["QueryPerformanceCounter", "rdtsc", "GetTickCount"],
        "calls": ["QueryPerformanceCounter", "GetTickCount", "GetTickCount64"],
        "regex": r'(QueryPerformanceCounter|rdtsc).*?(QueryPerformanceCounter|rdtsc)',
        "min_score": 2
    },
    {
        "label": "AntiTamper_IntegrityCheck",
        "category": "anticheat",
        "keywords": ["checksum", "crc32", ".text", "VirtualProtect"],
        "calls": ["VirtualQuery", "VirtualProtect", "NtQueryVirtualMemory"],
        "min_score": 2
    },
    {
        "label": "AntiCheat_DriverCheck",
        "category": "anticheat",
        "keywords": ["DeviceIoControl", "IOCTL", "driver", "NtDeviceIoControlFile"],
        "calls": ["DeviceIoControl", "CreateFile", "NtDeviceIoControlFile"],
        "min_score": 2
    },
    {
        "label": "ProcessScan_AntiCheat",
        "category": "anticheat",
        "keywords": ["CreateToolhelp32Snapshot", "Process32First", "Process32Next"],
        "calls": ["CreateToolhelp32Snapshot", "Process32First", "Process32Next", "EnumProcesses"],
        "min_score": 2
    },

    # ── Game Engine (Unreal/Unity) ──
    {
        "label": "UE_ProcessEvent",
        "category": "engine",
        "keywords": ["ProcessEvent", "UFunction", "UObject", "FName"],
        "calls": ["ProcessEvent", "ProcessInternal"],
        "min_score": 2
    },
    {
        "label": "UE_GObjects",
        "category": "engine",
        "keywords": ["GObjects", "FUObjectArray", "ObjObjects", "GetObjectsOfClass"],
        "calls": [],
        "min_score": 1
    },
    {
        "label": "Unity_il2cpp_Init",
        "category": "engine",
        "keywords": ["il2cpp_init", "il2cpp_domain_get", "il2cpp_thread_attach"],
        "calls": ["il2cpp_init", "il2cpp_domain_get"],
        "min_score": 1
    },
    {
        "label": "Entity_GetPosition",
        "category": "engine",
        "keywords": ["GetActorLocation", "GetWorldPosition", "transform.position"],
        "calls": ["GetActorLocation", "GetComponentLocation"],
        "regex": r'(position|location|coord)\.(x|y|z)\s*=',
        "min_score": 2
    },

    # ── Memory / VM ──
    {
        "label": "VirtualAlloc_Exec",
        "category": "memory",
        "keywords": ["PAGE_EXECUTE_READWRITE", "VirtualAlloc", "0x40"],
        "calls": ["VirtualAlloc", "VirtualAllocEx", "NtAllocateVirtualMemory"],
        "min_score": 2
    },
    {
        "label": "Shellcode_Loader",
        "category": "memory",
        "keywords": ["VirtualAlloc", "memcpy", "CreateThread"],
        "calls": ["VirtualAlloc", "memcpy", "CreateThread"],
        "min_score": 3
    },
    {
        "label": "Manual_Map_DLL",
        "category": "memory",
        "keywords": ["IMAGE_DOS_HEADER", "IMAGE_NT_HEADERS", "IMAGE_SECTION_HEADER", "relocation"],
        "calls": ["VirtualAlloc", "memcpy"],
        "min_score": 3
    },

    # ── String / Obfuscation ──
    {
        "label": "String_Decrypt",
        "category": "obfuscation",
        "keywords": ["decrypt", "deobfuscate"],
        "regex": r'for\s*\(.*\)\s*\{[^}]*(\[\s*\w+\s*\]\s*\^|\bxor\b)',
        "min_score": 2
    },
    {
        "label": "VM_Handler_Dispatch",
        "category": "obfuscation",
        "keywords": ["opcode", "handler", "dispatch", "vm_context"],
        "regex": r'switch\s*\(\s*\w+\s*\)\s*\{(\s*case\s+\d+\s*:){5,}',
        "min_score": 2
    },
]


def match_function(decompiled_code: str) -> list:
    """Match decompiled code against all known patterns. Returns ranked matches."""
    if not decompiled_code or len(decompiled_code) < 20:
        return []

    code_upper = decompiled_code.upper()
    results = []

    for pattern in KNOWN_PATTERNS:
        score = 0

        # Check keywords
        for kw in pattern.get("keywords", []):
            if kw.upper() in code_upper:
                score += 1

        # Check function calls
        for call in pattern.get("calls", []):
            if call in decompiled_code:
                score += 1.5  # Calls are stronger signals

        # Check regex
        regex = pattern.get("regex")
        if regex:
            try:
                if re.search(regex, decompiled_code, re.DOTALL | re.IGNORECASE):
                    score += 2
            except Exception:
                pass

        if score >= pattern.get("min_score", 2):
            results.append({
                "label": pattern["label"],
                "category": pattern["category"],
                "confidence": min(score / 5.0, 1.0),  # Normalize to 0-1
                "score": score
            })

    # Sort by confidence
    results.sort(key=lambda x: x["confidence"], reverse=True)
    return results
