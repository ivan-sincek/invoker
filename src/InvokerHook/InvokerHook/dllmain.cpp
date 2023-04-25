// Copyright (c) 2019 Ivan Šincek

#include "pch.h"
#include <windows.h>
#pragma  comment(lib, "user32")

// NOTE: Basic hook example.

// NOTE: Change the seed to change the file hash.
int seed = 3301;

void Message(const char* msg) {
	MessageBoxA(0, msg, "Invoker", MB_OK);
}

// NOTE: Do not change the name of this method. This method is required.
// NOTE: Feel free to change the content of this method - make your own hook procedure.
extern "C" __declspec(dllexport) LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HC_ACTION) {
		PCWPSTRUCT data = (PCWPSTRUCT)lParam;
		// NOTE: Invoke a message box on each window close.
		if (data->message == WM_CLOSE) {
			Message("Hello from InvokerHook DLL!\n");
		}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// NOTE: Do not change the name of this method. This method is required.
// NOTE: Change the return value (i.e. hook type) as necessary.
extern "C" __declspec(dllexport) int GetHookType() {
	return WH_CALLWNDPROC;
	// return WH_CALLWNDPROCRET;
	// return WH_CBT;
	// return WH_DEBUG;
	// return WH_FOREGROUNDIDLE;
	// return WH_GETMESSAGE;
	// return WH_JOURNALPLAYBACK;
	// return WH_JOURNALRECORD;
	// return WH_KEYBOARD;
	// return WH_KEYBOARD_LL;
	// return WH_MOUSE;
	// return WH_MOUSE_LL;
	// return WH_MSGFILTER;
	// return WH_SHELL;
	// return WH_SYSMSGFILTER;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	switch (fdwReason) {
		// NOTE: You can also try to play with this.
		case DLL_PROCESS_ATTACH: { break; } // NOTE: This case will run on DLL load once per process - e.g. upon DLL injection.
		case DLL_PROCESS_DETACH: { break; } // NOTE: This case will run on DLL unload once per process.
		case DLL_THREAD_ATTACH:  { break; } // NOTE: This case will run on DLL load multiple times per process.
		case DLL_THREAD_DETACH:  { break; } // NOTE: This case will run on DLL unload multiple times per process.
	}
	return TRUE;
}
