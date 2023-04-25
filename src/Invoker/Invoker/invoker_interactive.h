// Copyright (c) 2019 Ivan Sincek
// v5.7.3

#ifndef INVOKER_INTERACTIVE
#define INVOKER_INTERACTIVE

#include <string>

// --------------------------------------- SECTION: GLOBALS

#define INVOKER_RUN_DEF 0 // Default
#define INVOKER_RUN_WMI 1 // Windows Management Instrumentation
#define INVOKER_RUN_DSC 2 // Direct System Calls
#define INVOKER_RUN_APC 3 // Asynchronous Procedure Calls

namespace InvokerInteractive {

	// --------------------------------------- SECTION: SYSTEM

	void InvokeCMD();

	void InvokePS();

	void InvokeWordMacro();

	void InvokeSystemShellsMenu();

	// --------------------------------------- SECTION: DIRECT SYSTEM CALLS

	void DSCMenu();

	// --------------------------------------- SECTION: WMI

	void WMISetNamespace();

	void WMIExecuteQuery();

	void WMIExecuteMethodMenu();

	void WMIMenu();

	// --------------------------------------- SECTION: PROCESSES

	void ReverseTCP();

	void ReverseTCP(std::string addr);

	void ShutDownProcess(int code = INVOKER_RUN_DEF);

	void RunProcess(int code = INVOKER_RUN_DEF);

	void DumpProcessMemory();

	void ManageProcessesMenu();

	// --------------------------------------- SECTION: EXECUTABLE IMAGE TAMPERING

	void ProcessHollowingWeb();

	void ProcessHollowingFile();

	void ProcessGhostingFile();

	void ExeImageTamperingMenu();

	// --------------------------------------- SECTION: BYTECODES

	void InjectBytecodeWeb(int code = INVOKER_RUN_DEF);

	void InjectBytecodeFile(int code = INVOKER_RUN_DEF);

	void InjectBytecodeMenu();

	// --------------------------------------- SECTION: DLLS & THREADS

	void InjectDLL(int code = INVOKER_RUN_DEF);

	void InjectDLLHook();

	void InjectDLLMenu();

	void InstallWindowsHook();

	void ListProcessDLLs();

	void DLLHijacking();

	// --------------------------------------- SECTION: TOKENS

	void EnableAccessTokenPrivs();

	void DuplicateAccessToken();

	// --------------------------------------- SECTION: FILES

	void DownloadFile();

	// --------------------------------------- SECTION: PERSISTENCE

	void EditRegistryKey();

	void ScheduleTask();

	// --------------------------------------- SECTION: SERVICES

	void UnquotedServicePaths();

	// --------------------------------------- SECTION: MISCELLANEOUS

	void ReplaceSystem32FilesMenu();

	// --------------------------------------- SECTION: MAIN

	void Title();

	void Usage();

	void Menu();

}

#endif
