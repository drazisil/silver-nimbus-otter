/* Reject reasons and error reporting for winlift. */
#ifndef WINLIFT_DIAGNOSTICS_H
#define WINLIFT_DIAGNOSTICS_H

typedef enum {
    PE_OK = 0,
    PE_ERR_OPEN,
    PE_ERR_TRUNCATED,
    PE_ERR_BAD_DOS_MAGIC,
    PE_ERR_BAD_NT_SIGNATURE,
    PE_ERR_NOT_I386,
    PE_ERR_IS_DLL,
    PE_ERR_NOT_EXECUTABLE,
    PE_ERR_PE32PLUS,
    PE_ERR_BAD_OPTHDR_MAGIC,
    PE_ERR_UNSUPPORTED_SUBSYSTEM,
    PE_ERR_HAS_DOTNET,
    PE_ERR_TLS_CALLBACKS,
    PE_ERR_DELAY_IMPORTS,
    PE_ERR_ORDINAL_IMPORT,
    PE_ERR_FORWARDED_IMPORT,
    PE_ERR_UNSUPPORTED_DLL,
    PE_ERR_UNSUPPORTED_FUNC,
    PE_ERR_MALFORMED,
    PE_ERR_IMAGEBASE_CONFLICT,
    PE_ERR_TOO_MANY_SECTIONS,
    PE_ERR_TOO_MANY_IMPORTS,
} pe_reject_reason_t;

typedef struct {
    pe_reject_reason_t reason;
    char message[256];
} pe_error_t;

void pe_error_set(pe_error_t *err, pe_reject_reason_t reason, const char *fmt, ...);

#endif /* WINLIFT_DIAGNOSTICS_H */
