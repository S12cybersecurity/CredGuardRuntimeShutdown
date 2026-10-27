# Cred Guard Runtime Shutdown
Runtime Credential Guard deactivation via `\LSA_ISO_DISABLE_CREDENTIAL_GUARD` + LSASS NT hash extraction (Win11 24H2)

---

## Overview

`LsaIso.exe` contains a thread, `DisableCredGuardWaitThread` that blocks on the named kernel event `\LSA_ISO_DISABLE_CREDENTIAL_GUARD`. Signaling it tears down the CredGuard credential provider at runtime, without a reboot, without a kernel driver.

The event DACL restricts `EVENT_MODIFY_STATE` to SYSTEM. The PoC reaches SYSTEM from a high integrity admin process by stealing and impersonating the token of `winlogon.exe` via `DuplicateTokenEx` + `ImpersonateLoggedOnUser`.

After a 3 second teardown window, any new interactive logon session materializes its NT hash in plain VTL0 LSASS memory. The PoC creates a test session via `LogonUserA` and scans LSASS for the hash at the Win11 24H2 `MSV1_0_PRIMARY_CREDENTIAL` offset `+0x1F6`

```
SeDebugPrivilege
    |
OpenProcess(winlogon) --> DuplicateTokenEx --> ImpersonateLoggedOnUser
    |
NtOpenEvent(\LSA_ISO_DISABLE_CREDENTIAL_GUARD) --> NtSetEvent
    |
RevertToSelf -- Sleep(3s)
    |
LogonUserA --> OpenProcess(lsass) --> scan for NT hash at +0x1F6
```

---

## Requirements

- Windows 11 24H2 (build 26200) with VBS + Credential Guard active
- High integrity admin process (for `SeDebugPrivilege`)
- No kernel driver required

---

## Build

```
gcc -o credguard_poc.exe credguard_poc.c -lntdll -lwincrypt -ldbghelp
```

---

## Usage

```
credguard_poc.exe <user> <domain> <password>
```

Default values if no arguments are passed: `sshuser` `.` `password`.

The account must exist on the target machine. `LogonUserA` creates the post-shutdown session whose hash will appear in LSASS.

---

## Notes

- The named event disappears after teardown. A second run on the same boot returns `STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034)`: CG is already off.
- Only sessions created **after** the shutdown are affected. Pre-existing sessions remain protected in VTL1.
- The `+0x1F6` hash offset is specific to Win11 24H2 build 26200. Verify the layout with a kernel debugger before running against a different build.
- A minidump via `MiniDumpWriteDump` is written to `C:\Windows\Temp\lsass_post.dmp` as an offline fallback. The LUID→session→credentials pointer chain lives in a `MEM_MAPPED` region not captured by the dump, so pypykatz will not find the hash via the usual chain walk, use the direct scan instead.

---

## Detection

| Indicator | Source |
|---|---|
| `NtOpenEvent` on `\LSA_ISO_DISABLE_CREDENTIAL_GUARD` | ETW Security Auditing event 4656 (Audit Kernel Object) |
| `OpenProcess(winlogon, PROCESS_QUERY_INFORMATION)` from non SYSTEM | Sysmon event 10 |
| `Win32_DeviceGuard.SecurityServicesRunning` drops from `[1,2]` to `[2]` | WMI polling |
| `LogonUserA` + `OpenProcess(lsass, VM_READ)` in same process | EDR behavioral correlation |

---
