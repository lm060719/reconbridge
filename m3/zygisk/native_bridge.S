// Scalar Android/Linux AAPCS64 and SysV AMD64 gateways.
// NativeFrame offsets are checked in native_abi.h. No vector/aggregate/varargs ABI.
.text
#if defined(__aarch64__)
.macro RB_PROXY n
.p2align 2
.global rb_proxy_\n
.hidden rb_proxy_\n
.type rb_proxy_\n, %function
rb_proxy_\n:
    hint #34
    mov x16, #\n
    b rb_native_entry
.size rb_proxy_\n, .-rb_proxy_\n
.endm
.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63
RB_PROXY \n
.endr

.p2align 2
.type rb_native_entry, %function
rb_native_entry:
.cfi_startproc
    sub sp, sp, #176
.cfi_def_cfa_offset 176
    stp x29, x30, [sp, #160]
.cfi_offset 29, -16
.cfi_offset 30, -8
    add x29, sp, #160
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp d0, d1, [sp, #64]
    stp d2, d3, [sp, #80]
    stp d4, d5, [sp, #96]
    stp d6, d7, [sp, #112]
    add x9, sp, #176
    str x9, [sp, #144]
    mov w0, w16
    mov x1, sp
    bl rb_native_dispatch
    ldr x0, [sp, #128]
    ldr d0, [sp, #136]
    ldp x29, x30, [sp, #160]
    add sp, sp, #176
.cfi_def_cfa_offset 0
    ret
.cfi_endproc
.size rb_native_entry, .-rb_native_entry

.global rb_native_call
.hidden rb_native_call
.type rb_native_call, %function
rb_native_call:
.cfi_startproc
    hint #34
    stp x29, x30, [sp, #-32]!
.cfi_def_cfa_offset 32
.cfi_offset 29, -32
.cfi_offset 30, -24
    str x19, [sp, #16]
.cfi_offset 19, -16
    mov x29, sp
    mov x19, x1
    mov x16, x0
    ldp x0, x1, [x19, #0]
    ldp x2, x3, [x19, #16]
    ldp x4, x5, [x19, #32]
    ldp x6, x7, [x19, #48]
    ldp d0, d1, [x19, #64]
    ldp d2, d3, [x19, #80]
    ldp d4, d5, [x19, #96]
    ldp d6, d7, [x19, #112]
    blr x16
    str x0, [x19, #128]
    str d0, [x19, #136]
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
.cfi_def_cfa_offset 0
    ret
.cfi_endproc
.size rb_native_call, .-rb_native_call

#elif defined(__x86_64__) && !defined(_WIN32)
.macro RB_PROXY n
.p2align 4
.global rb_proxy_\n
.hidden rb_proxy_\n
.type rb_proxy_\n, @function
rb_proxy_\n:
    endbr64
    mov $\n, %r10d
    jmp rb_native_entry
.size rb_proxy_\n, .-rb_proxy_\n
.endm
.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63
RB_PROXY \n
.endr

.p2align 4
.type rb_native_entry, @function
rb_native_entry:
.cfi_startproc
    sub $168, %rsp
.cfi_def_cfa_offset 176
    mov %rdi, 0(%rsp)
    mov %rsi, 8(%rsp)
    mov %rdx, 16(%rsp)
    mov %rcx, 24(%rsp)
    mov %r8, 32(%rsp)
    mov %r9, 40(%rsp)
    movq %xmm0, 64(%rsp)
    movq %xmm1, 72(%rsp)
    movq %xmm2, 80(%rsp)
    movq %xmm3, 88(%rsp)
    movq %xmm4, 96(%rsp)
    movq %xmm5, 104(%rsp)
    movq %xmm6, 112(%rsp)
    movq %xmm7, 120(%rsp)
    lea 176(%rsp), %rax
    mov %rax, 144(%rsp)
    mov %r10d, %edi
    mov %rsp, %rsi
    call rb_native_dispatch
    mov 128(%rsp), %rax
    movq 136(%rsp), %xmm0
    add $168, %rsp
.cfi_def_cfa_offset 8
    ret
.cfi_endproc
.size rb_native_entry, .-rb_native_entry

.global rb_native_call
.hidden rb_native_call
.type rb_native_call, @function
rb_native_call:
.cfi_startproc
    endbr64
    push %r12
.cfi_def_cfa_offset 16
.cfi_offset %r12, -16
    push %r13
.cfi_def_cfa_offset 24
.cfi_offset %r13, -24
    sub $24, %rsp
.cfi_def_cfa_offset 48
    mov %rdi, %r13
    mov %rsi, %r12
    mov 48(%r12), %rax
    mov %rax, 0(%rsp)
    mov 56(%r12), %rax
    mov %rax, 8(%rsp)
    movq 64(%r12), %xmm0
    movq 72(%r12), %xmm1
    movq 80(%r12), %xmm2
    movq 88(%r12), %xmm3
    movq 96(%r12), %xmm4
    movq 104(%r12), %xmm5
    movq 112(%r12), %xmm6
    movq 120(%r12), %xmm7
    mov 0(%r12), %rdi
    mov 8(%r12), %rsi
    mov 16(%r12), %rdx
    mov 24(%r12), %rcx
    mov 32(%r12), %r8
    mov 40(%r12), %r9
    xor %eax, %eax
    call *%r13
    mov %rax, 128(%r12)
    movq %xmm0, 136(%r12)
    add $24, %rsp
.cfi_def_cfa_offset 24
    pop %r13
.cfi_def_cfa_offset 16
    pop %r12
.cfi_def_cfa_offset 8
    ret
.cfi_endproc
.size rb_native_call, .-rb_native_call
#else
#error Unsupported Native scalar ABI (requires AArch64 or SysV x86_64)
#endif
.hidden rb_native_dispatch
.section .note.GNU-stack,"",%progbits
