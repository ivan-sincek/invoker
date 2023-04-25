// Copyright (c) 2019 Ivan Sincek
// v5.7.3

#ifndef INVOKER
#define INVOKER

#include <string>
#include <windows.h>
#include <NetCon.h>

// --------------------------------------- SECTION: GLOBALS

#define STREAM_BUFFER_SIZE                    2048

#define SVC_START                                1
#define SVC_STOP                                 2
#define SVC_RESTART                              3

#define MiniDumpWithFullMemory          0x00000002
#define STATUS_SUCCESS                  0x00000000

#define OBJ_CASE_INSENSITIVE            0x0000040L
#define FILE_SUPERSEDED                 0x00000000
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020
#define FileDispositionInformation              13
#define ProcessBasicInformation                  0
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001

namespace Invoker {

	// --------------------------------------- SECTION: STRINGS

	std::string Base64Decode(std::string str);

	bool IsPositiveNumber(std::string str);

	bool StrToDWORD(std::string str, PDWORD out);

	std::string StrToLower(std::string str);

	std::string StrToUpper(std::string str);

	std::string Trim(std::string str);

	std::string Input(std::string msg);

	std::string StrStripLeftFirst(std::string str, std::string delim, bool clear = false);

	std::string StrStripRightFirst(std::string str, std::string delim, bool clear = false);

	std::string StrStripLeftLast(std::string str, std::string delim, bool clear = false);

	std::string StrStripRightLast(std::string str, std::string delim, bool clear = false);

	typedef struct _URL {
		std::string schema;
		std::string domain;
		std::string port;
		std::string path;
		std::string pathFull;
		std::string query;
		std::string fragment;
	} URL, * PURL;

	URL ParseURL(std::string url);

	// --------------------------------------- SECTION: SYSTEM

	std::string GetFilePath(HMODULE hModule = NULL);

	std::string GetWinDir(bool system = false);

	void Pause();

	void Clear();

	bool IsShellAccessible();

	void ShellExec(std::string command = "");

	void PowerShellExec(std::string command = "");

	// --------------------------------------- SECTION: FILES

	bool MakeFile(std::string file, std::string data = "");

	std::string GetFileContent(std::string file);

	typedef HRESULT(__stdcall* URLDownloadToFileA)(LPUNKNOWN pCaller, LPCSTR szURL, LPCSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB);

	bool DownloadFile(std::string addr, std::string file);

	bool GetFileMappingAddr(std::string file, PDWORD size, LPVOID* addr);

	// --------------------------------------- SECTION: PERSISTENCE

	bool EditRegistryKey(PHKEY hKey, std::string subkey = "", std::string name = "", std::string data = "");

	bool ScheduleTask(std::string name, std::string user, std::string file, std::string args = "");

	// --------------------------------------- SECTION: WMI

	typedef struct _WMI {
		std::string language;
		std::string space;
	} WMI, * PWMI;

	void WMIExecuteQuery(std::string query, std::string language = "WQL", std::string space = "ROOT\\CIMV2");

	bool WMIExecuteMethod(std::string instance, std::string cls, std::string method, std::string space = "ROOT\\CIMV2");

	bool WMIExecuteMethod(std::string instance, std::string cls, std::string method, std::string property, std::string value, std::string space = "ROOT\\CIMV2");

	// --------------------------------------- SECTION: PROCESSES

	bool ReverseTCP(std::string host, std::string port, std::string file, std::string args = "");

	bool IsWoW64(DWORD pid);

	bool GetProcessID(PDWORD out);

	bool ShutDownProcess(DWORD pid);

	bool RunProcess(std::string file, std::string args = "", PHANDLE hToken = NULL);

	typedef bool(__stdcall* MiniDumpWriteDump)(HANDLE hProcess, DWORD ProcessId, HANDLE hFile, DWORD DumpType, PVOID ExceptionParam, PVOID UserStreamParam, PVOID CallbackParam);

	bool DumpProcessMemory(DWORD pid);

	// --------------------------------------- SECTION: THREADS

	DWORD GetProcessMainThreadID(DWORD pid, PHANDLE hSnapshot);

	bool GetProcessThreadID(DWORD pid, PDWORD out);

	typedef struct _HOOK {
		DWORD ltid;
		bool active;
		std::string file;
		DWORD rtid;
	} HOOK, * PHOOK;

	void HookJob(PHOOK info);

	bool RemoveHookThread(PHOOK info);

	bool CreateHookThread(PHOOK info);

	// --------------------------------------- SECTION: BYTECODES

	std::string GetWebContent(std::string host, DWORD port, std::string path = "/", bool secure = false, std::string method = "GET", std::string agent = "Invoker/5.5");

	std::string ExtractPayload(std::string data, std::string element = "<invoker>payload</invoker>", std::string placeholder = "payload");

	bool InjectBytecode(DWORD pid, std::string bytecode);

	bool InjectBytecodeAPC(DWORD pid, std::string bytecode);

	// --------------------------------------- SECTION: EXECUTABLE IMAGE TAMPERING

	typedef NTSTATUS(__stdcall* NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

	// NOTE: Read more at https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-block.
	typedef struct _BASE_RELOCATION_BLOCK {
		DWORD Address;
		DWORD Size;
	} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

	typedef struct _BASE_RELOCATION_ENTRY {
		USHORT Offset : 12;
		USHORT Type : 4;
	} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

	bool ProcessHollowing(std::string bytecode, std::string file, std::string args = "");

	// -------------------- PROCESS GHOSTING

	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;

	typedef void(__stdcall* RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

	typedef struct _OBJECT_ATTRIBUTES {
		ULONG Length;
		HANDLE RootDirectory;
		PUNICODE_STRING ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;
		PVOID SecurityQualityOfService;
	} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

	#ifndef InitializeObjectAttributes
	#define InitializeObjectAttributes(p, n, a, r, s) { \
		(p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
		(p)->RootDirectory = r;                         \
		(p)->Attributes = a;                            \
		(p)->ObjectName = n;                            \
		(p)->SecurityDescriptor = s;                    \
		(p)->SecurityQualityOfService = NULL;           \
	}
	#endif

	typedef struct _IO_STATUS_BLOCK {
		union {
			NTSTATUS Status;
			PVOID Pointer;
		};
		ULONG_PTR Information;
	} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

	typedef NTSTATUS(__stdcall* NtOpenFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);

	typedef struct _FILE_DISPOSITION_INFORMATION {
		BOOLEAN DeleteFile;
	} FILE_DISPOSITION_INFORMATION, * PFILE_DISPOSITION_INFORMATION;

	typedef NTSTATUS(__stdcall* NtSetInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, DWORD FileInformationClass);

	typedef NTSTATUS(__stdcall* NtWriteFile)(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

	typedef NTSTATUS(__stdcall* NtCreateSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);

	typedef NTSTATUS(__stdcall* NtCreateProcessEx)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel);

	typedef struct _CURDIR {
		UNICODE_STRING DosPath;
		HANDLE Handle;
	} CURDIR, * PCURDIR;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		ULONG MaximumLength;
		ULONG Length;
		ULONG Flags;
		ULONG DebugFlags;
		HANDLE ConsoleHandle;
		ULONG ConsoleFlags;
		HANDLE StandardInput;
		HANDLE StandardOutput;
		HANDLE StandardError;
		CURDIR CurrentDirectory;
		UNICODE_STRING DllPath;
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
		PVOID Environment;
		ULONG StartingX;
		ULONG StartingY;
		ULONG CountX;
		ULONG CountY;
		ULONG CountCharsX;
		ULONG CountCharsY;
		ULONG FillAttribute;
		ULONG WindowFlags;
		ULONG ShowWindowFlags;
		UNICODE_STRING WindowTitle;
		UNICODE_STRING DesktopInfo;
		UNICODE_STRING ShellInfo;
		UNICODE_STRING RuntimeData;
		PVOID CurrentDirectories[32];
		ULONG EnvironmentSize;
		ULONG EnvironmentVersion;
		PVOID PackageDependencyData;
		ULONG ProcessGroupId;
		ULONG LoaderThreads;
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	typedef struct _PEB {
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		BOOLEAN Spare;
		HANDLE Mutant;
		PVOID ImageBaseAddress;
		PVOID LoaderData;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PVOID FastPebLock;
		PVOID FastPebLockRoutine;
		PVOID FastPebUnlockRoutine;
		ULONG EnvironmentUpdateCount;
		PVOID* KernelCallbackTable;
		PVOID EventLogSection;
		PVOID EventLog;
		PVOID FreeList;
		ULONG TlsExpansionCounter;
		PVOID TlsBitmap;
		ULONG TlsBitmapBits[2];
		PVOID ReadOnlySharedMemoryBase;
		PVOID ReadOnlySharedMemoryHeap;
		PVOID* ReadOnlyStaticServerData;
		PVOID AnsiCodePageData;
		PVOID OemCodePageData;
		PVOID UnicodeCaseTableData;
		ULONG NumberOfProcessors;
		ULONG NtGlobalFlag;
		BYTE Spare2[4];
		LARGE_INTEGER CriticalSectionTimeout;
		ULONG HeapSegmentReserve;
		ULONG HeapSegmentCommit;
		ULONG HeapDeCommitTotalFreeThreshold;
		ULONG HeapDeCommitFreeBlockThreshold;
		ULONG NumberOfHeaps;
		ULONG MaximumNumberOfHeaps;
		PVOID* ProcessHeaps;
		PVOID GdiSharedHandleTable;
		PVOID ProcessStarterHelper;
		PVOID GdiDCAttributeList;
		PVOID LoaderLock;
		ULONG OSMajorVersion;
		ULONG OSMinorVersion;
		ULONG OSBuildNumber;
		ULONG OSPlatformId;
		ULONG ImageSubSystem;
		ULONG ImageSubSystemMajorVersion;
		ULONG ImageSubSystemMinorVersion;
		ULONG GdiHandleBuffer[34];
		ULONG PostProcessInitRoutine;
		ULONG TlsExpansionBitmap;
		BYTE TlsExpansionBitmapBits[128];
		ULONG SessionId;
	} PEB, * PPEB;

	typedef struct _PROCESS_BASIC_INFORMATION {
		NTSTATUS ExitStatus;
		PPEB PebBaseAddress;
		ULONG_PTR AffinityMask;
		LONG BasePriority;
		HANDLE UniqueProcessId;
		HANDLE InheritedFromUniqueProcessId;
	} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

	typedef NTSTATUS(__stdcall* NtQueryInformationProcess)(HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

	typedef NTSTATUS(__stdcall* NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesRead);

	typedef NTSTATUS(__stdcall* RtlCreateProcessParametersEx)(PRTL_USER_PROCESS_PARAMETERS* pProcessParameters, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags);

	typedef NTSTATUS(__stdcall* NtCreateThreadEx)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);

	bool SetDeletePendingFileProcessParams(PHANDLE hProcess, PRTL_USER_PROCESS_PARAMETERS params, PROCESS_BASIC_INFORMATION pbInfo);

	bool RunDeletePendingFileThread(std::string file, LPVOID addr, DWORD size, PHANDLE hProcess, PHANDLE hThread);

	bool RunDeletePendingFileProcess(std::string tmp, LPVOID addr, DWORD size, PHANDLE hProcess);

	bool ProcessGhosting(std::string executable, std::string file);

	// --------------------------------------- SECTION: DLLS

	bool InjectDLL(DWORD pid, std::string file);

	bool InjectDLLAPC(DWORD pid, std::string file);

	void ListProcessDLLs(DWORD pid);

	typedef void(__stdcall* NcFreeNetconProperties)(NETCON_PROPERTIES* pProps);

	bool NetMan();

	// --------------------------------------- SECTION: TOKENS

	void EnableAccessTokenPrivs();

	HANDLE DuplicateAccessToken(DWORD pid);

	// --------------------------------------- SECTION: SERVICES

	std::string GetUnquotedServiceName();

	bool ManageService(std::string name, int task);

	// --------------------------------------- SECTION: MISCELLANEOUS

	bool ReplaceSystem32File(std::string dst, std::string src = "cmd.exe");

}

#endif
