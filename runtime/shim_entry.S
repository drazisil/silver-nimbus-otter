/* Real ELF entry point for the converted binary. Reads argc/argv/envp
 * directly off the initial process stack (the standard Linux i386 process
 * entry ABI: [esp]=argc, [esp+4]=argv[0]..., NULL, envp[0]..., NULL, auxv)
 * since we bypass glibc's _start/__libc_start_main entirely, initializes
 * shim state, then jumps to the original PE entry point. shim_pe_entry_target
 * is a plain data word that winlift patches (at a fixed, symbol-resolved
 * offset - see stub_patch.c) with ImageBase + AddressOfEntryPoint for
 * whichever program is being converted; the shim blob itself is built once,
 * generically, at winlift's own compile time. */

    .section .data
    .globl shim_pe_entry_target
shim_pe_entry_target:
    .long 0

    .section .text
    .globl _start
    .type _start, @function
_start:
    xor %ebp, %ebp
    mov (%esp), %eax          /* argc */
    lea 4(%esp), %ebx         /* argv */
    lea 4(%ebx,%eax,4), %ecx  /* envp = argv + 4*(argc+1) */

    push %ecx
    push %ebx
    push %eax
    call shim_startup_init
    add $12, %esp

    mov shim_pe_entry_target, %eax
    jmp *%eax
    /* not reached: mainCRTStartup-style entry points always terminate via
     * exit()/ExitProcess(), never return here */

    .section .note.GNU-stack,"",@progbits
