# Contributing to Dragon C2

Thanks for your interest in contributing. This project is a personal research framework but contributions are welcome, especially in areas listed below.

## How to report bugs

Open an issue on GitHub with:

- What you were doing (command, transport, level)
- What you expected to happen
- What actually happened
- Any error messages or logs
- OS versions (server and client)

## How to suggest features

Open an issue with the title starting with `[FEATURE]` and describe:

- What the feature does
- Why it would be useful
- Any ideas on how to implement it

## How to submit code

1. Fork the repository
2. Create a branch with a descriptive name (`fix-shell-hang`, `add-dns-transport`, etc.)
3. Make your changes
4. Test on at least one transport
5. Open a pull request with a clear description of what you changed and why

## Code style

- Language: C (C11 standard)
- Comments: English, simple and direct
- Function comments use this format:

```c
/* =========================================================================
 * function_name
 *
 * Short description of what the function does. One or two sentences
 * about behavior, parameters, and return value.
 * ====================================================================== */
```

## Areas where help is needed

- **DNS transport** - covert channel using DNS TXT/CNAME queries
- **IoT compatible transport** - for IoT environments
- **SOCKS5 proxy** - tunnel traffic through clients
- **.NET CLR runner** - execute .NET assemblies in memory (clr_runner.dll exists but is not integrated)
- **Sleep/jitter** - server-side command to change beacon timing at runtime
- **GUI** - C# interface
- **Evasion** - ETW patching, AMSI bypass, syscall stubs
- **Testing** - stress tests, edge cases, disconnection handling, large file transfers
- **Documentation** - DETECTION.md with YARA/Sigma/Suricata rules

## What not to submit

- Code that only works on a specific machine or environment
- Features without any testing
- Changes that break existing functionality without discussion first
- Malware samples or stolen credentials

## Questions

If you are not sure about something, open an issue and ask before writing code. It saves time for everyone.