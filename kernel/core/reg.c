#include "..\..\includes\shared.h"
#include "..\..\includes\reg_defs.h"

LIST_ENTRY g_reg_list;
KSPIN_LOCK g_reg_lock;

void reg_init(void)
{
    InitializeListHead(&g_reg_list);
    KeInitializeSpinLock(&g_reg_lock);
}

void reg_cleanup(void)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_reg_entry re;

    KeAcquireSpinLock(&g_reg_lock, &irql);
    while (!IsListEmpty(&g_reg_list)) {
        entry = RemoveHeadList(&g_reg_list);
        re = CONTAINING_RECORD(entry, hidden_reg_entry, list);
        ExFreePool(re);
    }
    KeReleaseSpinLock(&g_reg_lock, irql);
}

NTSTATUS reg_add(PCWSTR path)
{
    phidden_reg_entry re;
    KIRQL irql;
    UNICODE_STRING us;
    ULONG alloc_size;

    RtlInitUnicodeString(&us, path);
    alloc_size = sizeof(hidden_reg_entry) + us.MaximumLength;
    re = (phidden_reg_entry)ExAllocatePoolWithTag(NonPagedPool, alloc_size, 'rgch');
    if (!re) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(re, sizeof(hidden_reg_entry));
    re->path.Length = us.Length;
    re->path.MaximumLength = us.MaximumLength;
    re->path.Buffer = (PWCH)((PUCHAR)re + sizeof(hidden_reg_entry));
    RtlCopyMemory(re->path.Buffer, us.Buffer, us.MaximumLength);
    KeAcquireSpinLock(&g_reg_lock, &irql);
    InsertTailList(&g_reg_list, &re->list);
    KeReleaseSpinLock(&g_reg_lock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS reg_remove(PCWSTR path)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_reg_entry re;
    UNICODE_STRING us;

    RtlInitUnicodeString(&us, path);
    KeAcquireSpinLock(&g_reg_lock, &irql);
    for (entry = g_reg_list.Flink; entry != &g_reg_list; entry = entry->Flink) {
        re = CONTAINING_RECORD(entry, hidden_reg_entry, list);
        if (RtlCompareUnicodeString(&re->path, &us, TRUE) == 0) {
            RemoveEntryList(&re->list);
            KeReleaseSpinLock(&g_reg_lock, irql);
            ExFreePool(re);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_reg_lock, irql);
    return STATUS_NOT_FOUND;
}

BOOLEAN reg_is_hidden(PCUNICODE_STRING path)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_reg_entry re;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_reg_lock, &irql);
    for (entry = g_reg_list.Flink; entry != &g_reg_list; entry = entry->Flink) {
        re = CONTAINING_RECORD(entry, hidden_reg_entry, list);
        if (RtlCompareUnicodeString(&re->path, path, TRUE) == 0) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_reg_lock, irql);
    return found;
}

ULONG reg_count(void)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    ULONG count = 0;

    KeAcquireSpinLock(&g_reg_lock, &irql);
    for (entry = g_reg_list.Flink; entry != &g_reg_list; entry = entry->Flink)
        count++;
    KeReleaseSpinLock(&g_reg_lock, irql);
    return count;
}

NTSTATUS reg_list(PVOID buffer, ULONG size, PULONG needed)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_reg_entry re;
    preg_request rr = (preg_request)buffer;
    ULONG count = 0;

    *needed = reg_count() * sizeof(reg_request);
    if (size < *needed) return STATUS_BUFFER_TOO_SMALL;
    KeAcquireSpinLock(&g_reg_lock, &irql);
    for (entry = g_reg_list.Flink; entry != &g_reg_list; entry = entry->Flink) {
        re = CONTAINING_RECORD(entry, hidden_reg_entry, list);
        RtlZeroMemory(rr[count].path, sizeof(rr[count].path));
        if (re->path.Length > 0 && re->path.Length < sizeof(rr[count].path))
            RtlCopyMemory(rr[count].path, re->path.Buffer, re->path.Length);
        count++;
    }
    KeReleaseSpinLock(&g_reg_lock, irql);
    return STATUS_SUCCESS;
}
