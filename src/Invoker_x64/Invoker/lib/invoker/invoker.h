// Copyright (c) 2019 Ivan Šincek
// v4.2.1

#ifndef INVOKER
#define INVOKER

#include <string>
#include <windows.h>

#define CHECK_SHELL_ACCESS "echo Invoker 1>nul"
#define STREAM_BUFFER_SIZE 1024
#define WMI_ARRAY_SIZE       16
#define SVC_START             1
#define SVC_STOP              2
#define SVC_RESTART           3

// --------------------------------------- SECTION: STRINGS

bool StrToDWORD(std::string str, PDWORD out);

std::string StrToLower(std::string str);

std::string StrToUpper(std::string str);

std::string Trim(std::string str);

std::string Input(std::string msg);

bool IsPositiveNumber(std::string str);

std::string StrStripFront(std::string str, std::string delim, bool clear = false);

std::string StrStripBack(std::string str, std::string delim, bool clear = false);

struct url {
	std::string schema;
	std::string host;
	std::string port;
	std::string path;
	std::string pathFull;
	std::string query;
	std::string fragment;
};

url ParseURL(std::string addr);

/*
std::string GetErrorMessage(DWORD code);
*/

// --------------------------------------- SECTION: SHELL

std::string GetFilePath(HMODULE hModule = NULL);

void Pause();

void Clear();

bool IsShellAccessible();

void ShellExec(std::string command = "");

void PowerShellExec(std::string command = "");

// --------------------------------------- SECTION: FILES

bool MakeFile(std::string file, std::string data = "");

std::string ReadFile(std::string file);

bool AppendFile(std::string file, std::string data);

typedef int(__stdcall* MyURLDownloadToFile)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK);

bool DownloadFile(std::string addr, std::string file);

// --------------------------------------- SECTION: PERSISTENCE

bool EditRegistryKey(PHKEY hKey, std::string subkey, std::string name, std::string data);

bool ScheduleTask(std::string name, std::string user, std::string file, std::string args = "");

// --------------------------------------- SECTION: WMI

struct wmi {
	std::string space;
	std::string language;
};

void WMIRunQuery(std::string query, std::string language = "WQL", std::string space = "ROOT\\CIMV2");

bool WMIExecuteMethod(std::string instance, std::string cls, std::string method, std::string space = "ROOT\\CIMV2");

bool WMIExecuteMethod(std::string instance, std::string cls, std::string method, std::string property, std::string value, std::string space = "ROOT\\CIMV2");

// --------------------------------------- SECTION: PROCESSES

bool ReverseTCP(std::string host, std::string port, std::string file, std::string args);

bool IsWoW64(DWORD pid);

bool GetProcessID(PDWORD out);

bool ShutDownProcess(DWORD pid);

bool RunProcess(std::string file, std::string args = "", PHANDLE hToken = NULL);

typedef int(__stdcall* MyMiniDumpWriteDump)(HANDLE, DWORD, HANDLE, DWORD, PVOID, PVOID, PVOID);

bool DumpProcessMemory(DWORD pid);

// --------------------------------------- SECTION: BYTECODES

std::string GetWebContent(std::string host, DWORD port, std::string path = "/", bool secure = false, std::string method = "GET", std::string agent = "Invoker/4.0.0");

std::string ExtractPayload(std::string data, std::string element = "<invoker>payload</invoker>", std::string placeholder = "payload");

bool InjectBytecode(DWORD pid, std::string bytecode);

// --------------------------------------- SECTION: DLLS

bool InjectDLL(DWORD pid, std::string file);

void ListProcessDLLs(DWORD pid);

struct hook {
	DWORD tid;
	bool active;
	std::string file;
};

void HookJob(hook* info);

bool CreateHookThread(hook* info);

bool RemoveHookThread(hook* info);

// --------------------------------------- SECTION: TOKENS

void EnableAccessTokenPrivs();

HANDLE DuplicateAccessToken(DWORD pid);

// --------------------------------------- SECTION: SERVICES

std::string GetUnquotedServiceName();

bool ManageService(std::string name, int task);

// --------------------------------------- SECTION: MISCELLANEOUS

bool ReplaceSystem32File(std::string file);

#endif
