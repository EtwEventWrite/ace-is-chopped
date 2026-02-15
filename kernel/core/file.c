#include "..\..\includes\shared.h"
#include "..\..\includes\file_defs.h"

LIST_ENTRY g_file_list;
KSPIN_LOCK g_file_lock;

void file_init(void)
{
    InitializeListHead(&g_file_list);
    KeInitializeSpinLock(&g_file_lock);
}

void file_cleanup(void)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_file_entry fe;

    KeAcquireSpinLock(&g_file_lock, &irql);
    while (!IsListEmpty(&g_file_list)) {
        entry = RemoveHeadList(&g_file_list);
        fe = CONTAINING_RECORD(entry, hidden_file_entry, list);
        ExFreePool(fe);
    }
    KeReleaseSpinLock(&g_file_lock, irql);
}

NTSTATUS file_add(PCWSTR path)
{
    phidden_file_entry fe;
    KIRQL irql;
    UNICODE_STRING us;
    ULONG alloc_size;

    RtlInitUnicodeString(&us, path);
    alloc_size = sizeof(hidden_file_entry) + us.MaximumLength;
    fe = (phidden_file_entry)ExAllocatePoolWithTag(NonPagedPool, alloc_size, 'flch');
    if (!fe) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(fe, sizeof(hidden_file_entry));
    fe->path.Length = us.Length;
    fe->path.MaximumLength = us.MaximumLength;
    fe->path.Buffer = (PWCH)((PUCHAR)fe + sizeof(hidden_file_entry));
    RtlCopyMemory(fe->path.Buffer, us.Buffer, us.MaximumLength);
    KeAcquireSpinLock(&g_file_lock, &irql);
    InsertTailList(&g_file_list, &fe->list);
    KeReleaseSpinLock(&g_file_lock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS file_remove(PCWSTR path)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_file_entry fe;
    UNICODE_STRING us;

    RtlInitUnicodeString(&us, path);
    KeAcquireSpinLock(&g_file_lock, &irql);
    for (entry = g_file_list.Flink; entry != &g_file_list; entry = entry->Flink) {
        fe = CONTAINING_RECORD(entry, hidden_file_entry, list);
        if (RtlCompareUnicodeString(&fe->path, &us, TRUE) == 0) {
            RemoveEntryList(&fe->list);
            KeReleaseSpinLock(&g_file_lock, irql);
            ExFreePool(fe);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_file_lock, irql);
    return STATUS_NOT_FOUND;
}

BOOLEAN file_is_hidden(PCUNICODE_STRING path)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_file_entry fe;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_file_lock, &irql);
    for (entry = g_file_list.Flink; entry != &g_file_list; entry = entry->Flink) {
        fe = CONTAINING_RECORD(entry, hidden_file_entry, list);
        if (RtlCompareUnicodeString(&fe->path, path, TRUE) == 0) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_file_lock, irql);
    return found;
}

ULONG file_count(void)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    ULONG count = 0;

    KeAcquireSpinLock(&g_file_lock, &irql);
    for (entry = g_file_list.Flink; entry != &g_file_list; entry = entry->Flink)
        count++;
    KeReleaseSpinLock(&g_file_lock, irql);
    return count;
}

NTSTATUS file_list(PVOID buffer, ULONG size, PULONG needed)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_file_entry fe;
    pfile_request fr = (pfile_request)buffer;
    ULONG count = 0;

    *needed = file_count() * sizeof(file_request);
    if (size < *needed) return STATUS_BUFFER_TOO_SMALL;
    KeAcquireSpinLock(&g_file_lock, &irql);
    for (entry = g_file_list.Flink; entry != &g_file_list; entry = entry->Flink) {
        fe = CONTAINING_RECORD(entry, hidden_file_entry, list);
        RtlZeroMemory(fr[count].path, sizeof(fr[count].path));
        if (fe->path.Length > 0 && fe->path.Length < sizeof(fr[count].path))
            RtlCopyMemory(fr[count].path, fe->path.Buffer, fe->path.Length);
        count++;
    }
    KeReleaseSpinLock(&g_file_lock, irql);
    return STATUS_SUCCESS;
}
