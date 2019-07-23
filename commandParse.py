# commandParse.py
# Created by Starwarsfan2099 on 4/22/2019

import utilities
import datetime
from pydbg.defines import *
from colorama import init, Fore
import os
import debugger
from sys import exit

init(autoreset=True)
currentTime = datetime.datetime.now()
utils = utilities.Utilities.getInstance()
dbg = debugger.debugger()


class Parser:
    __instance = None

    @staticmethod
    def getInstance():                                      # several modules.
        """ Static access method. """
        if Parser.__instance == None:
            Parser()
        return Parser.__instance

    def __init__(self):
        Parser.__instance = self
        self.processName = "pywindbg"
        self.fileMode = False
        self.debug = False
        self.variables = {
            "executable": False,
            "verbose": False,
            "debug": False,
            "crash-mode": False,
            "file-mode": False,
            "logging": False,
            "logfile": "log-%s.txt" % currentTime.strftime("%Y-%m-%d-%H-%M"),
            "pid": 0,
            "hide-debugger": False
        }

    def seeHelp(self):
        utils.dbgPrint("\n[-] Invalid command usage. Use \"help\" for help.\n", Fore.RED)

    def help(self):
        utils.dbgPrint("\n Commands:", Fore.GREEN)
        utils.dbgPrint(" p* | print stuff                   Prints stuff. Use ?p for more help.")
        utils.dbgPrint(" e  | exit                          Exits the debugger and closes the process if active.")
        utils.dbgPrint(" cl | clear                         Clear the console.")
        utils.dbgPrint(" s  | set VARIABLE VALUE            Set a variable.")
        utils.dbgPrint(" ?  | help                          This help menu.")

        utils.dbgPrint("\n")

        utils.dbgPrint(" a  | attach PID                    Attach to a process ID.")
        utils.dbgPrint(" d  | detach                        Detach from a process.")
        utils.dbgPrint(" l  | list NAME|PID                 List current PID's, or search one by name or PID.")
        utils.dbgPrint(" o  | open EXE                      Launch and attach to an executable.")
        utils.dbgPrint(" r  | run ARGS                      Starts the opened process with args.")
        utils.dbgPrint(" c  | continue                      Continue execution after hitting a breakpoint.")
        utils.dbgPrint(" b* | set breakpoints               Setting breakpoints. Use ?b for more help.")
        utils.dbgPrint(" fr | resolve FUNC LIB              Returns the address for a function from a dll.")
        utils.dbgPrint(" dc | dump_context                  Returns current EIP disassembled and stack unwind.")
        utils.dbgPrint(" di | dump_info EXE|DLL|PID         Return information on PID, or debugging EXE, or supplied DLL.")
        utils.dbgPrint(" sr | set_reg REG VAL ID            Sets register REG to VAL in thread ID, all threads if no ID is specified.")
        utils.dbgPrint(" id | inject_dll PID DLL            Injects DLL into Process PID.")

        utils.dbgPrint("\n")

        utils.dbgPrint("Tools:", Fore.GREEN)
        utils.dbgPrint(" pm | process_monitor               Starts monitoring all created processes.")
        utils.dbgPrint(" fm | file_monitor DIR              Monitors file modification, creation, and deletion within DIR.")

        utils.dbgPrint("\n")

        utils.dbgPrint(" Variables:", Fore.GREEN)
        utils.dbgPrint("      verbose | True|False          Enables more output.")
        utils.dbgPrint("      debug   | True|False          Enables debugging output for development and bug hunting.")
        utils.dbgPrint("      logging | True|False          Enable logging to FILE.")
        utils.dbgPrint("      logfile | FILE.txt            Text file to log to, must be .txt.")
        utils.dbgPrint("   crash-mode | True|False          Enables crash mode.")
        utils.dbgPrint("    file-mode | True|False          Enables file hooking mode.")
        utils.dbgPrint("hide-debugger | True|False          Enables file hooking mode.")

        utils.dbgPrint("\n")

        utils.dbgPrint(" More help:", Fore.GREEN)
        utils.dbgPrint(" ?p | ?print                        Print methods help.")
        utils.dbgPrint(" ?b | ?breakpoint                   Breakpoint methods help.")

        utils.dbgPrint("\n")

    def printHelp(self):
        utils.dbgPrint(" \nPrint help:", Fore.GREEN)
        utils.dbgPrint(" pv | print_var VARIABLE           Specifically prints a debugger variable.")
        utils.dbgPrint(" pr | print_reg REGISTER           Prints the value in the specified REGISTER")
        utils.dbgPrint("\n")

    def breakpointHelp(self):
        utils.dbgPrint(" \nBreakpoint help:", Fore.GREEN)
        utils.dbgPrint(" b  | break ADDRESS                 Sets a soft breakpoint at address.")
        utils.dbgPrint(" bf | break_func FUNCTION DLL       Sets a soft breakpoint on a function imported from a dll.")
        # utils.dbgPrint(" bh | break_hard ADDRESS            Sets a hardware breakpoint at address.")
        # utils.dbgPrint(" bm | break_mem ADDRESS             Sets a memory breakpoint at address.")
        utils.dbgPrint("\n")

    def runCommand(self, command):
        if self.variables["logging"] is True:
            utils.dbgLogFileWrite("\n[%s]> %s" % (self.processName, command))                     # Adds prompt to log
        if command == '':                                                                       # If nothing is entered
            return
        elif command.split()[0] == 'set' or command.split()[0] == 's':                          # s or set
            self.variableParse(command)
        elif command == 'clear' or command == 'cl':                                             # cl or clear
            os.system("cls")
        elif command.split()[0] == 'l' or command.split()[0] == 'list':                         # l or list
            if len(command.split()) == 1:
                dbg.processList()
            else:
                dbg.processList(searchName=str(command.split()[1]))
        elif command == 'help' or command == "?":                                               # ? or help
            self.help()
        elif command.split()[0] == 'pm' or command.split()[0] == "process_monitor":             # pm or process_monitor
            self.startProcessMonitor()
        elif command.split()[0] == 'fm' or command.split()[0] == "file_monitor":                # fm or file_monitor
            self.startFileMonitor(command)
        elif command[0] == 'p' or command.split()[0][:6] == 'print_':                           # p or print_*
            self.printParse(command)
        elif command == "exit" or command == "e":                                               # e or exit
            utils.dbgPrint("\n[*] Closing processes, files, and exiting.\n", Fore.GREEN)
            if self.variables["logging"] is True:
                utils.dbgLogFileClose()
            exit()
        elif command == "?p" or command == "?print":                                            # ?p or ?print
            self.printHelp()
        elif command == "?b" or command == "?breakpoint":                                       # ?b or ?breakpoint
            self.breakpointHelp()
        elif command.split()[0][0] == "b" or command.split()[0][:5] == "break":                 # b* or break*
            self.breakpointParse(command)
        elif command.split()[0] == 'r' or command.split()[0] == "run":                          # r or run
            if self.fileMode is True:
                dbg.enableFileMode()
            dbg.run()
        elif command.split()[0] == 'c' or command.split()[0] == "continue":                     # c or continue
            dbg.continueRunning()
            return DBG_CONTINUE
        elif command.split()[0] == 'd' or command.split()[0] == "detach":                       # d or detach
            dbg.detach()
            self.processName = dbg.processName
        elif command.split()[0] == 'fr' or command.split()[0] == "resolve":                     # fr or resolve
            if len(command.split()) < 3:
                utils.dbgPrint("\n[-] Improper arguments. See help with ?.\n", Fore.RED)
                return
            dbg.getDllFunctionAddress(command.split()[1], command.split()[2])
        elif command.split()[0] == "a" or command.split()[0] == "attach":                       # a or attach
            if len(command.split()) > 1:
                self.attach(command.split()[1])
                self.processName = dbg.processName
                return
            else:
                utils.dbgPrint("\n[-] Provide a PID to attach to.\n", Fore.RED)
                return
        elif command.split()[0] == "o" or command.split()[0] == "open":                         # o or open
            if len(command.split()) > 1:
                self.openAndAttach(command.split()[1])
                return
            else:
                utils.dbgPrint("\n[-] Provide a path to an executable to launch.\n", Fore.RED)
                return
        elif command.split()[0] == 'dc' or command.split()[0] == "dump_context":                 # dc or dump_context
            dbg.dumpContext()
        elif command.split()[0] == 'sr' or command.split()[0] == "set_reg":                 # sr or set_register
            if len(command.split()) < 3:
                utils.dbgPrint("[-] Not enough args supplied.")
                return False
            elif len(command.split()) == 3:
                dbg.setRegister(command.split()[1].upper(), int(command.split()[2], 0))
            else:
                dbg.setRegister(command.split()[1].upper(), int(command.split()[2], 0), int(command.split()[3]))
        elif command.split()[0] == 'id' or command.split()[0] == "inject_dll":                   # id or inject_dll
            if len(command.split()) != 3:
                utils.dbgPrint("\n[-] Improper args supplied.", Fore.RED)
                return False
            dbg.dllInject(int(command.split()[1]), command.split()[2])
        elif command.split()[0] == 'di' or command.split()[0] == "dump_info":                    # di or dump_info
            dbg.dumpInfo(command)
        else:
            self.seeHelp()

    def printParse(self, command):
        command = command.split()
        if command[0] == 'pv' or command[0] == 'print_var':                          # Print variable
            input = command[1].lower()
            variable = self.checkVariable(input)
            if variable is not None:
                utils.dbgPrint("\n[*] %s = %s\n" % (input, variable))
            else:
                utils.dbgPrint("\n[-] Invalid variable name.\n", Fore.RED)
        elif command[0] == 'pr' or command[0] == 'print_register':                  # Print register
            if len(command) is 1:
                dbg.dumpRegisters()
            elif len(command) == 2:
                register = command[1].upper()
                utils.dbgPrint("")
                value = dbg.getRegister(register)
                if value is False:
                    utils.dbgPrint("\n[-] Error, check register name.", Fore.RED)
                    return False
            else:
                register = command[1].upper()
                thread = int(command[2].upper())
                value = dbg.getRegister(register, thread)
                if value is False:
                    utils.dbgPrint("\n[-] Error, check register name or thread id.", Fore.RED)
                    return False
                utils.dbgPrint("\n[*] (Thread: %d) %s: 0x%08x" % (thread, register, value), Fore.GREEN)

    def breakpointParse(self, command):
        command = command.split()
        if command[0] == "b" or command[0] == "break":
            if len(command) < 3:
                utils.dbgPrint("\n[-] Not enough arguments supplied.\n", Fore.RED)
                return False
            dbg.softBreakpointSet(command[1])
            return True
        elif command[0] == "bf" or command[0] == "break_func":
            if len(command) < 2:
                utils.dbgPrint("\n[-] Not enough arguments supplied.\n", Fore.RED)
                return False
            dbg.softBreakpointSetFunction(command[1], command[2], self.breakpointCommandHandler)
            return True

    def breakpointCommandHandler(self, dbgInstance):
        status = None
        while status != DBG_CONTINUE:
            status = self.runCommand(raw_input(utils.dbgPrint("\n[%s]> " % self.processName, Fore.GREEN, inputLine=True)))
        return DBG_CONTINUE

    def checkVariable(self, variable):
        if variable in self.variables.keys():
            output = self.variables[variable]
        else:
            output = None
        return output

    def variableParse(self, command):
        command = command.split()
        if len(command) < 3:
            utils.dbgPrint("\n[-] Incorrect usage, it should be \'set VARIABLE VALUE\'\n", Fore.RED)
            return False
        input = command[1].lower().strip()
        value = command[2].strip()
        if input in self.variables:
            if input == "logfile":                                                      # Logfile
                if ".txt" in value:
                    self.variables[input] = value
                    utils.dbgPrint("\n%s = %s\n" % (input, str(self.variables[input])))
                    return
                else:
                    utils.dbgPrint("\n[-] Must be a .txt file\n", Fore.RED)
                    return
            elif input == "pid":                                                        # PID
                self.variables[input] = int(value)
            elif input == "verbose":                                                    # Verbose
                if value.lower() == "true":
                    self.variables[input] = True
                    dbg.setVerbose(True)
                elif value.lower() == "false":
                    self.variables[input] = False
                    dbg.setVerbose(False)
                else:
                    utils.dbgPrint("\n[-] Incorrect variable value given\n", Fore.RED)
                    return
            elif input == "debug":                                                    # Debug
                if value.lower() == "true":
                    self.variables[input] = True
                    self.debug = True
                    dbg.setDebug(True)
                elif value.lower() == "false":
                    self.variables[input] = False
                    self.debug = False
                    dbg.setDebug(False)
                else:
                    utils.dbgPrint("\n[-] Incorrect variable value given\n", Fore.RED)
                    return
            elif input == "crash-mode":                                                # Crash Mode
                if value.lower() == "true":
                    self.variables[input] = True
                    dbg.enableCrashMode()
                elif value.lower() == "false":
                    self.variables[input] = False
                    dbg.disableCrashMode()
                else:
                    utils.dbgPrint("\n[-] Incorrect variable value given\n", Fore.RED)
                    return
            elif input == "file-mode":  # Crash Mode
                if value.lower() == "true":
                    self.variables[input] = True
                    self.fileMode = True
                elif value.lower() == "false":
                    self.variables[input] = False
                    self.fileMode = False
                    dbg.disableFileMode()
                else:
                    utils.dbgPrint("\n[-] Incorrect variable value given\n", Fore.RED)
                    return
            elif input == "hide-debugger":                                              # Hide debugger
                if value.lower() == "true":
                    self.variables[input] = True
                    dbg.enableHidden()
                elif value.lower() == "false":
                    self.variables[input] = False
                    dbg.disableHidden()
                else:
                    utils.dbgPrint("\n[-] Incorrect variable value given\n", Fore.RED)
                    return
            elif input == "logging":                                                    # Logging
                if value.lower() == "true":
                    self.variables[input] = True
                    utils.logging = True
                    utils.dbgLogFileCreate(self.variables["logfile"])
                elif value.lower() == "false":
                    self.variables[input] = False
                    utils.logging = False
                    try:
                        utils.dbgLogFileClose()
                    except:
                        utils.dbgPrint("\n[-] Never created logfile\n", Fore.RED)
                else:
                    utils.dbgPrint("\n[-] Incorrect variable value given\n", Fore.RED)
                    return
            else:
                self.seeHelp()
                return
        else:
            utils.dbgPrint("\n[-] Incorrect variable name given\n", Fore.RED)
            return
        utils.dbgPrint("\n%s = %s\n" % (input, str(self.variables[input])), verbose=self.debug)
        return True

    def attach(self, pid):
        if not isinstance(int(pid), (int, long)):
            utils.dbgPrint("\n[-] Invalid PID given\n", Fore.RED)
            return False
        self.variables["pid"] = int(pid)
        utils.dbgPrint("\n[*] Attempting to attach to PID %d\n" % int(pid), Fore.GREEN)
        dbg.attachPID(int(pid))
        return True

    def openAndAttach(self, path):
        utils.dbgPrint("\n[*] Opening %s\n" % path, Fore.GREEN)
        self.processName = path.split("\\")[-1]
        dbg.loadExecutable(path, self.processName)
        return True

    def startProcessMonitor(self):
        utils.dbgPrint("\n[*] Starting process monitor...", Fore.GREEN)
        utils.dbgPrint("\n[*] Press Ctrl-C once and wait a few seconds to kill the process monitor...", Fore.GREEN)
        dbg.processMonitor()

    def startFileMonitor(self, command):
        utils.dbgPrint("\n[*] Starting file monitor...", Fore.GREEN)
        utils.dbgPrint("\n[*] Press Ctrl-C once and wait for another exception to get caught, then the tool will exit cleanly.", Fore.GREEN)
        dbg.fileMonitor(command)
