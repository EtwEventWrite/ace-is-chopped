#ifndef reg_defs_h
#define reg_defs_h

#include <ntddk.h>

typedef struct _hidden_reg_entry {
    UNICODE_STRING path;
    LIST_ENTRY list;
} hidden_reg_entry, *phidden_reg_entry;

#endif
