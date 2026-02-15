#ifndef net_defs_h
#define net_defs_h

#include <ntddk.h>

typedef struct _hidden_net_entry {
    ULONG local_port;
    ULONG remote_port;
    ULONG local_addr;
    ULONG remote_addr;
    ULONG pid;
    ULONG protocol;
    LIST_ENTRY list;
} hidden_net_entry, *phidden_net_entry;

#endif
