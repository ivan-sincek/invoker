// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the INVOKERHOOK_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// INVOKERHOOK_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef INVOKERHOOK_EXPORTS
#define INVOKERHOOK_API __declspec(dllexport)
#else
#define INVOKERHOOK_API __declspec(dllimport)
#endif

// This class is exported from the dll
class INVOKERHOOK_API CInvokerHook {
public:
	CInvokerHook(void);
	// TODO: add your methods here.
};

extern INVOKERHOOK_API int nInvokerHook;

INVOKERHOOK_API int fnInvokerHook(void);
