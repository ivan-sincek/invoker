// InvokerHook.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "InvokerHook.h"


// This is an example of an exported variable
INVOKERHOOK_API int nInvokerHook=0;

// This is an example of an exported function.
INVOKERHOOK_API int fnInvokerHook(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
CInvokerHook::CInvokerHook()
{
    return;
}
