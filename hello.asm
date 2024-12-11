use64

SYS_write equ 1
    mov rdx ,rsi
    mov rsi ,rdi
    mov rdi ,1
    mov rax ,SYS_write
    syscall
    ret
