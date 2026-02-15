#ifndef driver_defs_h
#define driver_defs_h

#include <ntddk.h>

#define max_driver_name 260

typedef struct _hidden_driver_entry {
    WCHAR name[max_driver_name];
    LIST_ENTRY list;
} hidden_driver_entry, *phidden_driver_entry;

#endif
