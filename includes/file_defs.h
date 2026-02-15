#ifndef file_defs_h
#define file_defs_h

#include <ntddk.h>

typedef struct _hidden_file_entry {
    UNICODE_STRING path;
    LIST_ENTRY list;
} hidden_file_entry, *phidden_file_entry;

#endif
