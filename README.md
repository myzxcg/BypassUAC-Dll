# BypassUAC-Dll Version

[中文介绍](README.zh_CN.md)

Use COM components to bypass Windows UAC pop-up verification. In order to facilitate the use of white-exe + black-dll to bypass the anti-virus software, a Dll version was made. A certain degree of anti-virus processing is done on the source code.

## Usage

It is recommended to use a hijackable whitelist program to load the dll. Load.exe is also provided in Releases (only Loadlibrary() and Freelibrary() are used to load and release dll) for testing.

1. Start the exe without parameters:

    `Load.exe "C:\Users\Administrator\Desktop\Program.exe"`

2. Start the exe with parameters: (take Rawcap.exe as an example)

    `Load.exe "C:\Users\Administrator\Desktop\Rawcap.exe" "-s 20 192.168.1.1 C:\Users\Administrator\Desktop\1.pcap"`

**Note**: If a file needs to be generated in the exe startup parameter of BypassUAC, the file must be expressed in an absolute path, otherwise it will be generated in the `c:\windows\system32` directory. **Refer to Example 2**

## Compilation

The project uses the [Detours](https://github.com/microsoft/Detours) library to **hook Freelibrary() ** function. So you need to download [Detours](https://github.com/microsoft/Detours) first, and specify the compiled Detours library files and header files in Visual Studio.

If you modify the `#define SKey "..."` field in `header.h` (this field is the RC4 key), you also need to modify the value of Part1 in the `#define Part1 "..."` field . The modification method refers to the comments in the code.









