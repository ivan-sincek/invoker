// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the KEYBOARDHOOK_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// KEYBOARDHOOK_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef KEYBOARDHOOK_EXPORTS
#define KEYBOARDHOOK_API __declspec(dllexport)
#else
#define KEYBOARDHOOK_API __declspec(dllimport)
#endif

// This class is exported from the dll
class KEYBOARDHOOK_API CKeyboardHook {
public:
	CKeyboardHook(void);
	// TODO: add your methods here.
};

extern KEYBOARDHOOK_API int nKeyboardHook;

KEYBOARDHOOK_API int fnKeyboardHook(void);
