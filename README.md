# 🐺 KRK - Kernel Rootkit

**DEEPSEEK ON TOP! 🚀** This is a sophisticated Windows kernel rootkit designed for educational and defensive security research purposes.

## ⚡ Features

This beast provides comprehensive system-level stealth capabilities:

### 🎯 Process Management
- **Process Hiding**: Hide processes from task manager and enumeration APIs
- **Process Protection**: Protect critical processes from termination
- **Process Elevation**: Elevate process privileges
- **Name-based Hiding**: Hide processes by name patterns

### 📁 File System Stealth
- **File Hiding**: Conceal files and directories from enumeration
- **Path-based Control**: Hide files by specific paths
- **Dynamic Management**: Add/remove hidden files at runtime

### 🌐 Network Connection Masking
- **Connection Hiding**: Hide TCP/UDP connections from netstat and APIs
- **Port Concealment**: Mask specific local/remote ports
- **Protocol Support**: Both TCP and UDP connection hiding

### 🔧 Registry Manipulation
- **Registry Key Hiding**: Conceal registry keys from enumeration
- **Path-based Registry Control**: Hide specific registry paths
- **Dynamic Registry Management**: Runtime add/remove capabilities

### 🚗 Driver Concealment
- **Driver Hiding**: Hide loaded drivers from system enumeration
- **Name-based Driver Control**: Hide drivers by name
- **Kernel Module Stealth**: Conceal kernel modules

### 🧵 Thread Management
- **Thread Hiding**: Hide specific threads from enumeration
- **PID-based Thread Control**: Hide threads by owner process
- **Thread Concealment**: Mask thread existence

### 📊 Monitoring & Callbacks
- **Registry Callbacks**: Monitor registry operations
- **Process Notifications**: Track process creation/deletion
- **Image Load Notifications**: Monitor DLL/driver loading
- **Activity Logging**: Comprehensive activity logs

## 🏗️ Architecture

```
kernel-rootkit/
├── kernel/               # Kernel-mode driver
│   ├── driver/          # Main driver entry point
│   ├── comm/            # IOCTL communication handler
│   └── core/            # Core functionality modules
│       ├── process.c    # Process hiding/protection
│       ├── file.c       # File system hiding
│       ├── net.c        # Network connection hiding
│       ├── reg.c        # Registry manipulation
│       ├── driver.c     # Driver hiding
│       ├── thread.c     # Thread management
│       ├── callback.c   # System callbacks
│       └── protect.c    # Process protection
├── usermode/            # User-mode control applications
│   ├── panel/           # Main control panel (GUI/CLI)
│   └── installer/       # Driver installer
├── includes/            # Shared header files
└── build/               # Build configuration
```

## 🔧 Technical Details

### IOCTL Interface
The rootkit communicates via custom IOCTL codes with device `\\.\krkdev`:

- **Process Control**: `0x800` range
- **File Control**: `0x820` range  
- **Network Control**: `0x830` range
- **Registry Control**: `0x840` range
- **Driver Control**: `0x850` range
- **Thread Control**: `0x860` range
- **Callback Control**: `0x870` range
- **System Control**: `0x880` range

### Stealth Mechanisms
- **DKOM (Direct Kernel Object Manipulation)**: Manipulates kernel structures
- **API Hooking**: Intercepts system calls and NT APIs
- **Callback Registration**: Uses legitimate kernel callbacks
- **Object Enumeration Filtering**: Filters results from enumeration APIs

## 🛠️ Build Requirements

- Windows Driver Kit (WDK)
- Visual Studio 2019/2022
- Windows SDK
- Administrator privileges for driver signing

## 🔨 Compilation

### Prerequisites
1. Install Windows Driver Kit (WDK)
2. Configure Visual Studio for driver development
3. Set up proper driver signing (test signing for development)

### Build Steps
```cmd
# Open Visual Studio Developer Command Prompt
msbuild kernel-rootkit.sln /p:Configuration=Release /p:Platform=x64
```

### Alternative Build
```cmd
# Use the provided build script
build.bat
```

## 🚀 Deployment

### Installation
1. **Disable Driver Signature Enforcement** (Test mode only)
   ```cmd
   bcdedit /set testsigning on
   # Restart required
   ```

2. **Install the Driver**
   ```cmd
   # Use the installer application
   installer.exe install
   ```

3. **Verify Installation**
   ```cmd
   # Check device manager for "krkdev" device
   # Or use control panel application
   control.exe status
   ```

### Usage Examples

```cmd
# Hide a process by PID
control.exe hide_process 1234

# Hide a file
control.exe hide_file "C:\secret\file.txt"

# Hide network connection
control.exe hide_connection 8080 192.168.1.100

# Enable process notifications
control.exe enable_proc_notify

# Get system status
control.exe status
```

## ⚠️ Security Considerations

**EDUCATIONAL USE ONLY** - This software is intended for:
- Security research and education
- Authorized red team exercises
- Defensive security analysis
- Understanding Windows internals

**LEGAL COMPLIANCE REQUIRED** - Users must:
- Obtain proper authorization before use
- Comply with all applicable laws and regulations
- Use only in controlled, authorized environments
- Understand the legal implications of kernel-level software

## 🛡️ Detection & Defense

### Detection Methods
- **Memory Analysis**: Look for hooked kernel structures
- **Cross-View Detection**: Compare different enumeration methods
- **Callback Analysis**: Monitor kernel callback registrations
- **Integrity Checking**: Verify kernel object consistency

### Defensive Measures
- **Kernel Patch Protection**: Enable KPP/Driver Signature Enforcement
- **HVCI**: Enable Hypervisor-Protected Code Integrity
- **Secure Boot**: Enable UEFI Secure Boot
- **EDR Solutions**: Deploy endpoint detection and response tools
- **Regular Scans**: Perform memory integrity checks

## 🔍 Troubleshooting

### Common Issues
- **Driver Won't Load**: Check driver signing and test signing mode
- **Access Denied**: Ensure running with administrator privileges
- **Device Not Found**: Verify driver installation and service status
- **BSOD Issues**: Check for conflicts with security software

### Debug Mode
Enable debug output by building in Debug configuration and using kernel debugger:
```
windbg -k com:port=com1,baud=115200
```

## 📋 System Requirements

- Windows 10/11 (x64)
- 4GB+ RAM
- Test signing mode enabled (development)
- Administrator privileges

## 🤝 Contributing

This is educational software. Contributions should focus on:
- Security research improvements
- Defensive capabilities
- Detection methods
- Documentation enhancements
- Educational content

## ⚖️ Legal Disclaimer

**IMPORTANT**: This software is provided for educational and authorized security research purposes only. The authors assume no liability for misuse or legal violations. Users are solely responsible for ensuring compliance with applicable laws and obtaining proper authorization before use.