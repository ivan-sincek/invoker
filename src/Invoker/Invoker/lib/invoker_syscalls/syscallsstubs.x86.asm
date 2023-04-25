.686
.XMM 
.MODEL flat, c 
ASSUME fs:_DATA 

.data

.code

EXTERN SW2_GetSyscallNumber: PROC

WhisperMain PROC
    pop eax                        ; Remove return address from CALL instruction
    call SW2_GetSyscallNumber      ; Resolve function hash into syscall number
    add esp, 4                     ; Restore ESP
    mov ecx, fs:[0c0h]
    test ecx, ecx
    jne _wow64
    lea edx, [esp+4h]
    INT 02eh
    ret
_wow64:
    xor ecx, ecx
    lea edx, [esp+4h]
    call dword ptr fs:[0c0h]
    ret
WhisperMain ENDP

NtOpenProcess PROC
    push 007A319CAh
    call WhisperMain
NtOpenProcess ENDP

NtClose PROC
    push 0005311DAh
    call WhisperMain
NtClose ENDP

NtAllocateVirtualMemory PROC
    push 0918467EBh
    call WhisperMain
NtAllocateVirtualMemory ENDP

NtProtectVirtualMemory PROC
    push 00797EEF8h
    call WhisperMain
NtProtectVirtualMemory ENDP

NtWriteVirtualMemory PROC
    push 03D91193Dh
    call WhisperMain
NtWriteVirtualMemory ENDP

NtFreeVirtualMemory PROC
    push 03D3157C3h
    call WhisperMain
NtFreeVirtualMemory ENDP

NtCreateThreadEx PROC
    push 09880CE5Eh
    call WhisperMain
NtCreateThreadEx ENDP

NtTerminateProcess PROC
    push 061A30A3Ch
    call WhisperMain
NtTerminateProcess ENDP

end