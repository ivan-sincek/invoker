// KeyboardHook.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "KeyboardHook.h"


// This is an example of an exported variable
KEYBOARDHOOK_API int nKeyboardHook=0;

// This is an example of an exported function.
KEYBOARDHOOK_API int fnKeyboardHook(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
CKeyboardHook::CKeyboardHook()
{
    return;
}
