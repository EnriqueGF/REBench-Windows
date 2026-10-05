option casemap:none
.code

PUBLIC check_record
PUBLIC bad_length_branch
PUBLIC bad_flag_branch

check_record PROC
    cmp rcx, 100h
bad_length_branch::
    jae short rejected
    test dl, 20h
bad_flag_branch::
    jnz short rejected
    mov rax, rcx
    xor rax, rdx
    test al, 1
    jnz short rejected
    mov eax, 1
    ret
rejected:
    xor eax, eax
    ret
check_record ENDP
END
