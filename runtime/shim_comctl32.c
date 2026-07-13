/* comctl32.dll: only ordinal 17 (InitCommonControls) is supported - see
 * include/shim_abi.h. Registers the common-control window classes on real
 * Windows; safe as a no-op here since M2's user32 shim never creates a real
 * window in the first place. */

void __attribute__((stdcall)) shim_InitCommonControls(void) {
}
