IFDEF RAX

.code

EXTERN GetFunctionId: PROC

PerformSyscall PROC
	mov [rsp+08h],rcx
	mov [rsp+10h],rdx
	mov [rsp+18h],r8
	mov [rsp+20h],r9
	mov ecx,eax
	sub rsp,28h
	call GetFunctionId
	add rsp,28h
	mov rcx,[rsp+08h]
	mov rdx,[rsp+10h]
	mov r8,[rsp+18h]
	mov r9,[rsp+20h]
	mov r10,rcx
	syscall
	ret
PerformSyscall ENDP

ELSE

.model flat, C
.code

ASSUME FS:NOTHING
EXTERN GetFunctionId: PROC

PerformSyscall PROC
	push eax
	call GetFunctionId
	add esp,04h
	mov edx,fs:[0000000c0h]
	test edx,edx
	jz _is_real_32bit
	call edx
	ret
	_is_real_32bit:
	mov edx,esp
	sysenter
	ret
PerformSyscall ENDP

ENDIF

ZwClose_impl PROC
	mov eax,05d044c61h
	jmp PerformSyscall
ZwClose_impl ENDP

ZwOpenDirectoryObject_impl PROC
	mov eax,03176f0e9h
	jmp PerformSyscall
ZwOpenDirectoryObject_impl ENDP

ZwOpenSection_impl PROC
	mov eax,092bbde55h
	jmp PerformSyscall
ZwOpenSection_impl ENDP

ZwMapViewOfSection_impl PROC
	mov eax,0d5189bf4h
	jmp PerformSyscall
ZwMapViewOfSection_impl ENDP

ZwUnmapViewOfSection_impl PROC
	mov eax,0f2d04fd0h
	jmp PerformSyscall
ZwUnmapViewOfSection_impl ENDP

end