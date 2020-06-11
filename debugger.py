# encoding=utf8
# debugger.py
# Created by Starwarsfan2099 on 6/4/2019

import os
import pefile
import psutil
from colorama import Fore

import debuggerUtilities as dbgUtils
import utilities
from pydbg import *
from pydbg.defines import *
import injection

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
        utils.dbgPrint("[DEBUG] Path: %s" % path, Fore.GREEN, verbose=self.debug)
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
        except Exception as e:
            utils.dbgPrint("\n[-] Unable to attach to pid.\n", Fore.RED)
            utils.dbgPrint("[-] Error: %s\n" % e, Fore.RED, verbose=self.verbose)
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
        return True

    def disableHidden(self):
        utils.dbgPrint("\n[*] Debugger will  no longer be hidden.\n", Fore.GREEN)
        self.dbg.setHidden(False)
        return True

    def createSnapshot(self):
        self.dbg.process_snapshot()
        utils.dbgPrint("\n[+] Created snapshot of process.", Fore.GREEN)
        return True

    def restoreSnapshot(self):
        self.dbg.process_restore()
        utils.dbgPrint("\n[+] Restored snapshot of process.", Fore.GREEN)
        return True

    def processList(self, searchName=None, moreInfo=False):
        utils.dbgPrint("\n[+] Getting Process List...\n", Fore.GREEN)
        if searchName is None:
            for (pid, name) in self.dbg.enumerate_processes():
                if pid != os.getpid():
                    if moreInfo is False:
                        utils.dbgPrint("[+] Name: ", Fore.GREEN, secondLine="%s PID:%s" % (name, pid))
                    else:
                        self.pidInfo(pid)
                else:
                    if moreInfo is False:
                        utils.dbgPrint("[+] Name: %s PID:%s     <==[Current Debugger Process] " % (name, pid), Fore.GREEN)
                    else:
                        self.pidInfo(pid)
        else:
            for (pid, name) in self.dbg.enumerate_processes():
                if searchName.lower() in name.lower() or searchName in str(pid):
                    if pid != os.getpid():
                        if moreInfo is False:
                            utils.dbgPrint("[+] Name: ", Fore.GREEN, secondLine="%s PID:%s" % (name, pid))
                        else:
                            self.pidInfo(pid)
                    else:
                        if moreInfo is False:
                            utils.dbgPrint("[+] Name: %s PID:%s     <==[Current Debugger Process] " % (name, pid), Fore.GREEN)
                        else:
                            self.pidInfo(pid)
        utils.dbgPrint("")
        return True

    def pidInfo(self, pid):
        try:
            p = psutil.Process(pid)
            utils.dbgPrint("\n[*] Name: ", Fore.GREEN, secondLine="%s" % p.name())
            utils.dbgPrint("[*] Executable path: ", Fore.GREEN, secondLine="%s" % p.exe())
            utils.dbgPrint("[*] Working directory: ", Fore.GREEN, secondLine="%s" % p.cwd())
            command = ""
            for item in p.cmdline():
                command = command + item + " "
            utils.dbgPrint("[*] Command line: ", Fore.GREEN, secondLine="\"%s\"" % command.strip())
            utils.dbgPrint("[*] Process: ", Fore.GREEN, secondLine="%d" % p.pid)
            utils.dbgPrint("[*] Parent PID: ", Fore.GREEN, secondLine="%d" % p.ppid())
            utils.dbgPrint("[*] Status: ", Fore.GREEN, secondLine="%s" % p.status())
            utils.dbgPrint("[*] Username: ", Fore.GREEN, secondLine="%s" % p.username())
            utils.dbgPrint("[*] Process creation time: ", Fore.GREEN, secondLine="%f" % p.create_time())
            utils.dbgPrint("[*] Threads: ", Fore.GREEN, secondLine="%d\n" % p.num_threads())
        except psutil.NoSuchProcess:
            utils.dbgPrint("\n[-] Process with a PID of %d not found.\n" % pid, Fore.RED)
            return False
        except psutil.AccessDenied:
            utils.dbgPrint("\n[-] Process with a PID of %d could not be accessed.\n" % pid, Fore.RED)
            return False
        return True

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
        return True

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
                    executablePath = command.split(" ", 1)[1]
                    utils.dbgPrint("[DEBUG] Executable path: %s" % executablePath, Fore.GREEN, verbose=self.debug)
                    utils.dbgPrint("")
                    pe = pefile.PE(executablePath)
                    self.parseBinaryInfo(pe.dump_info())
                except WindowsError:
                    utils.dbgPrint("\n[-] Unable to find file %s\n" % command.split()[1], Fore.RED)
        return True

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
        return True

    def getLibraries(self):
        i = 0
        for modules in self.dbg.enumerate_modules():
            if i == 0:
                utils.dbgPrint("[*] Executable > %s" % modules[0], Fore.GREEN)
                i += 1
            else:
                utils.dbgPrint("[+] DLL Loaded(%s) > %s" % (modules[1], modules[0]), Fore.BLUE)
        return True

    def readMemory(self, address, length):
        address = int(address, 0)
        value = self.dbg.read_process_memory(address, int(length))
        hexValue = utils.toHex(value)
        utils.dbgPrint("\n[*] Value: ", Fore.GREEN, secondLine="%s\n" % value)
        utils.dbgPrint("\n[*] Hex: ", Fore.GREEN, secondLine="%s\n" % hexValue)
        return True

    def writeMemory(self, command):
        address = int(command.split()[1], 0)
        length = int(command.split()[2])
        data = command.split()[3]
        self.dbg.write_process_memory(address, data, length)
        utils.dbgPrint("\n[+] Wrote %s to 0x%08x\n" % (data, address), Fore.GREEN)
        return True

    def getDllFunctionAddress(self, function, library):
        try:
            address = self.dbg.func_resolve_debuggee(library, function)
        except Exception as e:
            utils.dbgPrint("\n[DEBUG] Got error: %s\n" % e, Fore.RED, verbose=self.debug)
            utils.dbgPrint("\n[-] Error reading memory, is debugger attached to a process?\n", Fore.RED)
            return False
        if address == 0:
            utils.dbgPrint("\n[-] %s not found in %s.dll or the dll was not found.\n" % (function, library), Fore.RED)
            return False
        else:
            utils.dbgPrint("\n[DEBUG] Function: %s DLL: %s" % (function, library), Fore.GREEN, verbose=self.debug)
            utils.dbgPrint("[DEBUG] Address: %s\n" % address, Fore.GREEN, verbose=self.debug)
            if address is None:
                utils.dbgPrint("\n[-] Error resolving function %s\n" % function, Fore.RED)
                return False
            else:
                utils.dbgPrint("\n[*] %s, %s.dll: 0x%08x\n" % (function, library.strip(".dll"), address), Fore.GREEN)
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

    def dumpSEH(self):
        output = ""
        seh_unwind = self.dbg.seh_unwind()
        utils.dbgPrint("[DEBUG]: SEH: %s" % seh_unwind, Fore.GREEN, verbose=self.debug)
        for i in xrange(len(seh_unwind)):
            (addr, handler) = seh_unwind[i]

            module = self.dbg.addr_to_module(handler)

            if module:
                module = module.szModule
            else:
                module = "[INVALID]"

            seh_unwind[i] = (addr, handler, "%s:%08x" % (module, handler))

        if len(seh_unwind):
            output += "\nSEH unwind:\n"
            for (addr, handler, handler_str) in seh_unwind:
                output += "%08x -> %s\n" % (addr, handler_str)

        utils.dbgPrint(output + "\n", Fore.GREEN)
        return True

    def dumpStack(self):
        output = ""
        stack_unwind = self.dbg.stack_unwind()
        utils.dbgPrint("[DEBUG]: Stack: %s" % stack_unwind, Fore.GREEN, verbose=self.debug)
        for i in xrange(len(stack_unwind)):
            addr = stack_unwind[i]
            module = self.dbg.addr_to_module(addr)

            if module:
                module = module.szModule
            else:
                module = "[INVALID]"

            stack_unwind[i] = "%s:%08x" % (module, addr)

        if len(stack_unwind):
            output += "\nStack unwind:\n"
            for entry in stack_unwind:
                output += "%s\n" % entry

        utils.dbgPrint(output + "\n", utilities.stack_color)
        return True

    def dumpRegisters(self):
        for thread_id in self.dbg.enumerate_threads():
            thread_handle = self.dbg.open_thread(thread_id)
            context = self.dbg.get_thread_context(thread_handle)
            utils.dbgPrint("\n[*] Thread id: %d" % thread_id, Fore.GREEN)
            hexRegister = "%08x" % context.Eip
            utils.dbgPrint("[*] EIP: 0x%08x, - Decimal: %d, ASCII: %s" % (context.Eip, context.Eip, hexRegister.strip().decode("hex")), Fore.GREEN)
            hexRegister = "%08x" % context.Esp
            utils.dbgPrint("[*] ESP: 0x%08x, - Decimal: %d, ASCII: %s" % (context.Esp, context.Esp, hexRegister.strip().decode("hex")),Fore.GREEN)
            hexRegister = "%08x" % context.Ebp
            utils.dbgPrint("[*] EBP: 0x%08x, - Decimal: %d, ASCII: %s" % (context.Ebp, context.Ebp, hexRegister.strip().decode("hex")), Fore.GREEN)
            hexRegister = "%08x" % context.Eax
            utils.dbgPrint("[*] EAX: 0x%08x, - Decimal: %d, ASCII: %s" % (context.Eax, context.Eax, hexRegister.strip().decode("hex")), Fore.GREEN)
            hexRegister = "%08x" % context.Ebx
            utils.dbgPrint("[*] EBX: 0x%08x, - Decimal: %d, ASCII: %s" % (context.Ebx, context.Ebx, hexRegister.strip().decode("hex")), Fore.GREEN)
            hexRegister = "%08x" % context.Ecx
            utils.dbgPrint("[*] ECX: 0x%08x, - Decimal: %d, ASCII: %s" % (context.Ecx, context.Ecx, hexRegister.strip().decode("hex")), Fore.GREEN)
            hexRegister = "%08x" % context.Edx
            utils.dbgPrint("[*] EDX: 0x%08x, - Decimal: %d, ASCII: %s" % (context.Edx, context.Edx, hexRegister.strip().decode("hex")), Fore.GREEN)
        return True

    def getRegister(self, register, thread=None):
        if thread is None:
            for thread_id in self.dbg.enumerate_threads():
                thread_handle = self.dbg.open_thread(thread_id)
                context = self.dbg.get_thread_context(thread_handle)
                if register == "EIP":
                    hexRegister = "%08x" % context.Eip
                    utils.dbgPrint("[*] (Thread %d) EIP: 0x%08x, - Decimal: %d, ASCII: %s" % (thread_id, context.Eip, context.Eip, hexRegister.strip().decode("hex")), Fore.GREEN)
                elif register == "ESP":
                    hexRegister = "%08x" % context.Esp
                    utils.dbgPrint("[*] (Thread %d) ESP: 0x%08x, - Decimal: %d, ASCII: %s" % (thread_id, context.Esp, context.Esp, hexRegister.strip().decode("hex")), Fore.GREEN)
                elif register == "EBP":
                    hexRegister = "%08x" % context.Ebp
                    utils.dbgPrint("[*] (Thread %d) EBP: 0x%08x, - Decimal: %d, ASCII: %s" % (thread_id, context.Ebp, context.Ebp, hexRegister.strip().decode("hex")), Fore.GREEN)
                elif register == "EAX":
                    hexRegister = "%08x" % context.Eax
                    utils.dbgPrint("[*] (Thread %d) EAX: 0x%08x, - Decimal: %d, ASCII: %s" % (thread_id, context.Eax, context.Eax, hexRegister.strip().decode("hex")), Fore.GREEN)
                elif register == "EBX":
                    hexRegister = "%08x" % context.Ebx
                    utils.dbgPrint("[*] (Thread %d) EBX: 0x%08x, - Decimal: %d, ASCII: %s" % (thread_id, context.Ebx, context.Ebx, hexRegister.strip().decode("hex")), Fore.GREEN)
                elif register == "ECX":
                    hexRegister = "%08x" % context.Ecx
                    utils.dbgPrint("[*] (Thread %d) ECX: 0x%08x, - Decimal: %d, ASCII: %s" % (thread_id, context.Ecx, context.Ecx, hexRegister.strip().decode("hex")), Fore.GREEN)
                elif register == "EDX":
                    hexRegister = "%08x" % context.Edx
                    utils.dbgPrint("[*] (Thread %d) EDX: 0x%08x, - Decimal: %d, ASCII: %s" % (thread_id, context.Edx, context.Edx, hexRegister.strip().decode("hex")), Fore.GREEN)
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
        return True

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
        return True

    def enableCrashMode(self):
        def check_accessv(dbg):
            if dbg.dbg.u.Exception.dwFirstChance:
                return DBG_EXCEPTION_NOT_HANDLED
            crash_bin = dbgUtils.crash_binning()
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
        utils.dbgPrint("\n[+] Crash mode hooks in place.\n", Fore.GREEN, verbose=self.verbose)
        return True

    def disableCrashMode(self):
        def doNothing(dbg):
            return DBG_EXCEPTION_HANDLED

        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, doNothing)
        return True

    def enableFileMode(self):
        def handler_CreateFileW(dbg):
            Filename = ""
            addr_FilePointer = self.dbg.read_process_memory(self.dbg.context.Esp + 0x4, 4)
            addr_FilePointer = struct.unpack("<L", addr_FilePointer)[0]
            Filename = self.dbg.smart_dereference(addr_FilePointer, True)
            utils.dbgPrint("[*] CreateFileW -> %s" % Filename, utilities.heap_color)
            return DBG_CONTINUE

        def handler_CreateFileA(dbg):
            offset = 0
            buffer_FileA = ""
            addr_FilePointer = self.dbg.read_process_memory(self.dbg.context.Esp + 0x4, 4)
            addr_FilePointer = struct.unpack("<L", addr_FilePointer)[0]
            buffer_FileA = self.dbg.smart_dereference(addr_FilePointer, True)
            utils.dbgPrint("[*] CreateFileA -> %s" % buffer_FileA, Fore.GREEN)
            return DBG_CONTINUE

        function2 = "CreateFileW"
        function3 = "CreateFileA"
        CreateFileW = self.dbg.func_resolve_debuggee("kernel32.dll", "CreateFileW")
        CreateFileA = self.dbg.func_resolve_debuggee("kernel32.dll", "CreateFileA")
        utils.dbgPrint("[*]Resolving %s @ %08x" % (function2, CreateFileW), Fore.GREEN)
        utils.dbgPrint("[*]Resolving %s @ Unknown" % function2, Fore.GREEN)
        utils.dbgPrint("[*]Resolving %s @ %08x" % (function3, CreateFileA), Fore.GREEN)
        utils.dbgPrint("[*]Resolving %s @ Unknown" % function2, Fore.GREEN)
        self.dbg.bp_set(CreateFileA, description="CreateFileA", handler=handler_CreateFileA)
        self.dbg.bp_set(CreateFileW, description="CreateFileW", handler=handler_CreateFileW)
        return True

    def disableFileMode(self):
        def doNothing(dbg):
            return DBG_EXCEPTION_HANDLED

        CreateFileW = self.dbg.func_resolve_debuggee("kernel32.dll", "CreateFileW")
        CreateFileA = self.dbg.func_resolve_debuggee("kernel32.dll", "CreateFileA")
        self.dbg.bp_set(CreateFileA, description="CreateFileA", handler=doNothing)
        self.dbg.bp_set(CreateFileW, description="CreateFileW", handler=doNothing)
        return True

    def dllInject(self, pid, dll):
        inject = injection.dllInject(pid, dll, self.verbose)
        if inject is True:
            utils.dbgPrint("[+] DLL injection completed.", Fore.GREEN)
            return True
        return False

    def shellcodeInject(self, pid):
        inject = injection.shellcodeInjectMapping(pid, self.verbose)
        if inject is True:
            utils.dbgPrint("[+] Shellcode injection completed.", Fore.GREEN)
            return True
        return False
