#include <windows.h>
#include <stdio.h>
#include <string.h>

#define service_name "kernelrootkit"
#define display_name "kernel rootkit driver"

int main(int argc, char *argv[])
{
    SC_HANDLE scm, svc;
    char path[MAX_PATH];
    int r = 0;

    if (argc < 2) {
        printf("usage: %s <install|start|stop|uninstall>\n", argv[0]);
        printf("  install   - install driver (requires .sys path in same dir or -path)\n");
        printf("  start     - start driver\n");
        printf("  stop      - stop driver\n");
        printf("  uninstall - remove driver\n");
        return 1;
    }

    if (GetModuleFileNameA(NULL, path, (DWORD)MAX_PATH) == 0) {
        printf("error: GetModuleFileName failed\n");
        return 1;
    }
    {
        char *p = strrchr(path, '\\');
        if (p) *(p + 1) = 0;
        else path[0] = 0;
        strcat(path, "kernel-rootkit.sys");
    }

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        printf("error: OpenSCManager failed (run as admin)\n");
        return 1;
    }

    if (_stricmp(argv[1], "install") == 0) {
        svc = CreateServiceA(scm, service_name, display_name, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL);
        if (svc) {
            printf("driver installed: %s\n", path);
            CloseServiceHandle(svc);
        } else {
            if (GetLastError() == ERROR_SERVICE_EXISTS)
                printf("service already exists\n");
            else
                printf("error: CreateService failed - place kernel-rootkit.sys in same directory\n");
            r = 1;
        }
    } else if (_stricmp(argv[1], "start") == 0) {
        svc = OpenServiceA(scm, service_name, SERVICE_START);
        if (svc) {
            if (StartServiceA(svc, 0, NULL))
                printf("driver started\n");
            else {
                DWORD err = GetLastError();
                if (err == ERROR_SERVICE_ALREADY_RUNNING)
                    printf("driver already running\n");
                else
                    printf("error: StartService failed %lu\n", err);
                r = 1;
            }
            CloseServiceHandle(svc);
        } else {
            printf("error: OpenService failed (install first)\n");
            r = 1;
        }
    } else if (_stricmp(argv[1], "stop") == 0) {
        SERVICE_STATUS st;
        svc = OpenServiceA(scm, service_name, SERVICE_STOP);
        if (svc) {
            if (ControlService(svc, SERVICE_CONTROL_STOP, &st))
                printf("driver stopped\n");
            else
                printf("error: ControlService failed %lu\n", GetLastError());
            CloseServiceHandle(svc);
        } else {
            printf("error: OpenService failed\n");
            r = 1;
        }
    } else if (_stricmp(argv[1], "uninstall") == 0) {
        svc = OpenServiceA(scm, service_name, DELETE);
        if (svc) {
            if (DeleteService(svc))
                printf("driver uninstalled\n");
            else
                printf("error: DeleteService failed (stop driver first)\n");
            CloseServiceHandle(svc);
        } else {
            printf("error: OpenService failed\n");
            r = 1;
        }
    } else {
        printf("unknown command: %s\n", argv[1]);
        r = 1;
    }

    CloseServiceHandle(scm);
    return r;
}
