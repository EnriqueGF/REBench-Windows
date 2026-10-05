option casemap:none
.code

PUBLIC unwind_target
unwind_target PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    sub rsp, 088h
    .allocstack 088h
    lea rbp, [rsp+020h]
    .setframe rbp, 020h
    .endprolog

    mov rax, rcx
    xor rax, rdx
    mov rbx, 0123456789ABCDEFh
    add rax, rbx

    lea rsp, [rbp+068h]
    pop rbx
    pop rbp
    ret
unwind_target ENDP
END
