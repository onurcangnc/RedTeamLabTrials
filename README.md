# RedTeamLabTrials

**EDR Evasion Research — AMSI/ETW Bypass + Native Win32 File Operations in C#**

> ⚠️ **Authorized Use Only.** This repository contains proof-of-concept implementations for educational and authorized red-team research. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

---

## Overview

Research sandbox for Windows offensive security tooling development. Demonstrates:

- **AMSI Patching** — Bypass `AmsiScanBuffer` via runtime memory modification
- **ETW Patching** — Disable `EtwEventWrite` via `ntdll.dll` memory patching
- **Native Win32 I/O** — File operations using raw Win32 API to bypass managed-code monitoring
- **Diagnostic Utilities** — System access modules demonstrating SAM/LSA/SSH/WiFi enumeration

---

## Repository Contents

| File | Description |
|------|-------------|
| `EdrEvader.cs` | AMSI + ETW dual patch with XOR-obfuscated paths and native Win32 file write |
| `EdrEvader_NoObfuscation.cs` | Same technique without string obfuscation (comparison baseline) |
| `sam_lsa_wifi_ssh.cs` | System diagnostics tool — SAM registry, LSA secrets, SSH key discovery, WiFi profile extraction |

---

## Technical Details

### AMSI Patch

Patches `AmsiScanBuffer` to always return `AMSI_RESULT_CLEAN`:

```
mov eax, 0x00005700    ; AMSI_RESULT_CLEAN
ret
```

### ETW Patch

Disables `EtwEventWrite` in `ntdll.dll`:

```
ret                     ; 0xC3 (immediate return)
```

### Why Raw Win32 API?

Standard `System.IO` methods are often hooked by EDR/AV at the CLR level. Raw `CreateFile` → `WriteFile` → `CloseHandle` operates below managed-code instrumentation.

---

## Build Requirements

- Windows OS (API-specific functionality)
- .NET 6.0+ SDK or `csc` compiler
- Administrator privileges (for AMSI/ETW patching and diagnostic modules)

```bash
csc EdrEvader.cs -out:EdrEvader.exe
```

---

## Detection Guidance (Blue Team)

| Technique | Detection Source |
|-----------|-----------------|
| AMSI patch | `VirtualProtect` on `amsi.dll` (Sysmon EID 10/11); missing `Microsoft-Windows-Amsi` events |
| ETW patch | Missing `EtwEventWrite` callbacks; silent security providers |
| SAM access | `RegOpenKeyEx` on `HKLM\SAM\SAM\Domains\Account\Users` (Sysmon EID 12/13) |
| LSA secrets | `LsaRetrievePrivateData` calls with unusual secret names |
| SSH key reads | File reads on `%USERPROFILE%\.ssh\id_*` (Sysmon EID 11) |
| WiFi extraction | `WlanGetProfile` with `WLAN_PROFILE_GET_PLAINTEXT_KEY` flag |

---

## Disclaimer

This material is provided for **authorized security testing, detection engineering, and educational purposes only.** The authors assume no liability for misuse. If you cannot distinguish between authorized testing and illegal activity, do not use this code.
