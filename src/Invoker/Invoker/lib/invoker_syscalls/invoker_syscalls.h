// Copyright (c) 2019 Ivan Sincek
// v5.7.3

#ifndef INVOKER_SYSCALLS
#define INVOKER_SYSCALLS

#include <string>
#include <windows.h>

// --------------------------------------- SECTION: GLOBALS

#define STATUS_SUCCESS 0x00000000

namespace InvokerSysCalls {

	// --------------------------------------- SECTION: PROCESSES

	bool ShutDownProcess(DWORD pid);

	// --------------------------------------- SECTION: BYTECODES

	bool InjectBytecode(DWORD pid, std::string bytecode);

	// --------------------------------------- SECTION: DLLS

	bool InjectDLL(DWORD pid, std::string file);

}

#endif
