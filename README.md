
# HashLyte

HashLyte is a Windows-based file investigation tool I built using C# and WPF to make it easier to investigate suspicious files on local and remote computers.

The idea came from working in cybersecurity and constantly needing to look up file hashes, check digital signatures, identify running processes, and determine whether a file was legitimate or potentially malicious.

Instead of manually running multiple commands or using several different tools, I wanted something that could collect this information in one place.

## Features

- **File Analysis:** Investigate files and collect information that can help determine whether they are suspicious.
- **SHA-256 Hashing:** Calculate file hashes for identification and threat intelligence lookups.
- **Digital Signatures:** Check whether files are digitally signed and identify their publishers.
- **VirusTotal Integration:** Generate VirusTotal lookup links using the file's SHA-256 hash.
- **Process Investigation:** Identify running processes and collect information about their associated files.
- **Windows Services:** Review services associated with files and executables.
- **Installed Programs:** Collect information about installed applications.
- **Remote Investigation:** Connect to remote Windows computers to investigate files without needing to physically access the device.
- **Windows Authentication:** Use the current Windows account for local investigations and administrator credentials for remote connections.

## How It Works

HashLyte collects information about files on Windows computers to help with security investigations.

For local investigations, the application uses the permissions of the currently logged-in Windows user.

For remote investigations, HashLyte allows you to provide Windows credentials with the necessary permissions to access the remote computer. It uses Windows networking and management functionality, including SMB and WMI, to retrieve information.

The collected information can then be reviewed through the application's interface.

HashLyte also generates VirusTotal links, making it easier to look up file hashes without manually copying and searching for them.

## Why I Built It

During security investigations, I found myself repeatedly using PowerShell, Windows utilities, and other tools to gather basic information about suspicious files.

I wanted to simplify that process.

HashLyte started as a way to combine some of the most common file investigation tasks into a single application.

The goal wasn't to replace an EDR platform or a full forensic investigation toolkit. I just wanted something lightweight that could quickly provide useful information when investigating a file or troubleshooting a system.

## Technologies

- C#
- .NET 10
- Windows Presentation Foundation (WPF)
- Windows Management Instrumentation (WMI)
- SMB
- SHA-256
- Windows Authentication

## Usage

HashLyte supports both local and remote Windows investigations.

### Local Investigation

Launch HashLyte and select the local investigation option.

The application uses your currently logged-in Windows account to collect information from the local computer.

### Remote Investigation

Enter the remote computer's hostname or IP address and provide Windows credentials with the required administrative permissions.

HashLyte connects to the remote system and retrieves the requested information.

Remote functionality requires appropriate network connectivity, permissions, and access to the necessary Windows management services.

## Notes

HashLyte was designed primarily for Windows environments and cybersecurity investigations.

Some functionality requires administrative permissions, particularly when investigating remote computers or accessing protected system resources.

Only use HashLyte on systems you own or have authorization to investigate.

This is a personal project that I plan to continue improving as I find additional features worth adding.

## Disclaimer

HashLyte is provided as-is and is intended to assist with file investigation and security analysis.

A valid digital signature or a clean hash lookup does not guarantee that a file is safe. Results should always be reviewed alongside other security information.
