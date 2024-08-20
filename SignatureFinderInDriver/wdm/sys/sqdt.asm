.code
;void __sidt(_Out_ void * gdtr)
__sgdt PROC
	sidt [rcx]
	ret
__sgdt ENDP

Read60 PROC
	xor	rax, rax
	in	al, 60h
	ret
Read60 ENDP
Int3 PROC
	int	3
	ret
Int3 ENDP

END