#include "diagnostics.h"

#include <stdarg.h>
#include <stdio.h>

void pe_error_set(pe_error_t *err, pe_reject_reason_t reason, const char *fmt, ...) {
    if (!err) return;
    err->reason = reason;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err->message, sizeof(err->message), fmt, ap);
    va_end(ap);
}
