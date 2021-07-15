// Copyright (c) 2021 Ivan Šincek
// v4.2.1

#ifndef INVOKER_SYSCALLS
#define INVOKER_SYSCALLS

#include <string>
#include <windows.h>

// --------------------------------------- SECTION: BYTECODES

bool DSCInjectBytecode(DWORD pid, std::string bytecode);

// --------------------------------------- SECTION: DLLS

bool DSCInjectDLL(DWORD pid, std::string file);

#endif
