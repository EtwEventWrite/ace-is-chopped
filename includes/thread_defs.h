#ifndef thread_defs_h
#define thread_defs_h

#include <ntddk.h>

typedef struct _hidden_thread_entry {
    ULONG tid;
    ULONG owner_pid;
    LIST_ENTRY list;
} hidden_thread_entry, *phidden_thread_entry;

#endif
