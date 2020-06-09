# commandParse.py
# Created by Starwarsfan2099 on 4/22/2019

from datetime import datetime
import os
from subprocess import check_output
from sys import exit

from colorama import init, Fore

import debugger
import utilities
import tools
from pydbg.defines import *

init(autoreset=True)
currentTime = datetime.now()
utils = utilities.Utilities.getInstance()
dbg = debugger.debugger()


class Parser:
    __instance = None

    @staticmethod
    def getInstance():
        """ Static access method. """
        if Parser.__instance is None:
            Parser()
        return Parser.__instance

    def __init__(self):
        Parser.__instance = self
        self.processName = "pywindbg"                                                       # Currently debugged process, 'pywindbg' to start out with
        self.fileMode = False                                                               # Debugger set to file mode
        self.debug = False                                                                  # Debug mode for debugging output
        self.variables = {                                                                  # Variables that can be set from the command line of the debugger
            "executable": False,                                                            # Executable to open and run
            "verbose": False,                                                               # Verbose mode
            "debug": False,                                                                 # Debug mode
            "crash-mode": False,                                                            # Crash mode
            "file-mode": False,                                                             # File hooking mode
            "logging": False,                                                               # Enable logging
            "logfile": "log-%s.txt" % currentTime.strftime("%Y-%m-%d-%H-%M"),               # Logfile to write to
            "pid": 0,                                                                       # PID to debug
            "hide-debugger": False                                                          # Enable hiding the debugger
        }

    @staticmethod
    def seeHelp():
        utils.dbgPrint("\n[-] Invalid command usage. Use \"help\" for help.\n", Fore.RED)

    @staticmethod
    def help():
        utils.dbgPrint("\n Commands:", Fore.GREEN)
        utils.dbgPrint(" p* | print stuff                   Prints stuff. Use ?p for more help.")
        utils.dbgPrint(" e  | exit                          Exits the debugger and closes the process if active.")
        utils.dbgPrint(" cl | clear                         Clear the console.")
        utils.dbgPrint(" s  | set VARIABLE VALUE            Set a variable.")
        utils.dbgPrint(" ?  | help                          This help menu.")
        utils.dbgPrint(" cm | command CMD                   Execute command CMD with command prompt..")

        utils.dbgPrint("\n")

        utils.dbgPrint(" a  | attach PID                    Attach to a process ID, or to the PID variable if set.")
        utils.dbgPrint(" d  | detach                        Detach from a process.")
        utils.dbgPrint(" l  | list NAME|PID                 List current PID's, or search one by name or PID. (l -m NAME|PID) shows more info.")
        utils.dbgPrint(" o  | open EXE                      Launch and attach to an executable, or the executable set in the EXECUTABLE variable.")
        utils.dbgPrint(" r  | run ARGS                      Starts the opened or attached process with args.")
        utils.dbgPrint(" c  | continue                      Continue execution after hitting a breakpoint.")
        utils.dbgPrint(" b* | set breakpoints               Setting breakpoints. Use ?b for more help.")
        utils.dbgPrint(" fr | resolve FUNC LIB              Returns the address for a function from a dll.")
        utils.dbgPrint(" dc | dump_context                  Returns current EIP disassembled and stack unwind.")
        utils.dbgPrint(" di | dump_info EXE|DLL|PID         Return information on PID, or debugging EXE, or supplied DLL.")
        utils.dbgPrint(" sr | set_reg REG VAL ID            Sets register REG to VAL in thread ID, all threads if no ID is specified.")
        utils.dbgPrint(" id | inject_dll PID DLL            Injects DLL into process PID.")
        utils.dbgPrint(" is | inject_shellcode PID          Injects sellcode from the shellcode.py file into process PID.")
        utils.dbgPrint(" wa | write_adr ADDR LEN DATA       Writes data to an address.")
        utils.dbgPrint(" ds | dump_seh                      Dump the top of the SEH handler.")
        utils.dbgPrint(" dt | dump_stack                    Dump the top of the stack.")
        utils.dbgPrint(" sc | snapshot_create               Create a process snapshot.")
        utils.dbgPrint(" sr | snapshot_restore              Restore the processes snapshot.")

        utils.dbgPrint("\n")

        utils.dbgPrint("Tools:", Fore.GREEN)
        utils.dbgPrint(" pm | process_monitor               Starts monitoring all created processes.")
        utils.dbgPrint(" fm | file_monitor DIR              Monitors file modification, creation, and deletion within DIR.")

        utils.dbgPrint("\n")

        utils.dbgPrint(" Variables:", Fore.GREEN)
        utils.dbgPrint("          pid | PID                 Set a pid to attach to.")
        utils.dbgPrint("   executable | PATH                Set the path for an executable to be launched and attached to.")
        utils.dbgPrint("      verbose | True|False          Enables more output.")
        utils.dbgPrint("      debug   | True|False          Enables debugging output for development and bug hunting.")
        utils.dbgPrint("      logging | True|False          Enable logging to FILE.")
        utils.dbgPrint("      logfile | FILE.txt            Text file to log to, must be .txt.")
        utils.dbgPrint("   crash-mode | True|False          Enables crash mode.")
        utils.dbgPrint("    file-mode | True|False          Enables file hooking mode.")
        utils.dbgPrint("hide-debugger | True|False          Hide the debugger after first breakpoint.")

        utils.dbgPrint("\n")

        utils.dbgPrint(" More help:", Fore.GREEN)
        utils.dbgPrint(" ?p | ?print                        Print methods help.")
        utils.dbgPrint(" ?b | ?breakpoint                   Breakpoint methods help.")

        utils.dbgPrint("\n")

    @staticmethod
    def printHelp():
        utils.dbgPrint(" \nPrint help:", Fore.GREEN)
        utils.dbgPrint(" pv | print_var VARIABLE           Specifically prints a debugger variable.")
        utils.dbgPrint(" pr | print_reg REGISTER           Prints the value in the specified REGISTER")
        utils.dbgPrint(" pa | print_adr ADDRESS LENGTH     Prints the value stored in memory at ADDRESS")
        utils.dbgPrint("\n")

    @staticmethod
    def breakpointHelp():
        utils.dbgPrint(" \nBreakpoint help:", Fore.GREEN)
        utils.dbgPrint(" b  | break ADDRESS                 Sets a soft breakpoint at address.")
        utils.dbgPrint(" bf | break_func FUNCTION DLL       Sets a soft breakpoint on a function imported from a dll.")
        # utils.dbgPrint(" bh | break_hard ADDRESS            Sets a hardware breakpoint at address.")
        # utils.dbgPrint(" bm | break_mem ADDRESS             Sets a memory breakpoint at address.")
        utils.dbgPrint("\n")

    # Main function that takes a command and determines if teh command is an allowed command and executes the necessary functions
    def runCommand(self, command):
        splitCommand = command.split()
        if self.variables["logging"] is True:
            utils.dbgLogFileWrite("\n[%s]> %s" % (self.processName, command))             # Adds prompt to log
        if command == '':                                                                 # If nothing is entered
            return
        elif splitCommand[0] == 'set' or splitCommand[0] == 's':                          # s or set
            self.variableParse(command)
        elif command == 'clear' or command == 'cl':                                       # cl or clear
            os.system("cls")
        elif splitCommand[0] == 'l' or splitCommand[0] == 'list':                         # l or list
            if len(splitCommand) == 2:
                dbg.processList(searchName=str(splitCommand[1]))
            elif len(splitCommand) == 3:
                if splitCommand[1] == "-m":
                    dbg.processList(searchName=str(splitCommand[2]), moreInfo=True)
                else:
                    dbg.processList()
            else:
                dbg.processList()
        elif command == 'help' or command == "?":                                         # ? or help
            self.help()
        elif splitCommand[0] == 'pm' or splitCommand[0] == "process_monitor":             # pm or process_monitor
            self.startProcessMonitor()
        elif splitCommand[0] == 'fm' or splitCommand[0] == "file_monitor":                # fm or file_monitor
            self.startFileMonitor(command)
        elif command[0] == 'p' or splitCommand[0][:6] == 'print_':                        # p or print_*
            self.printParse(command)
        elif command == "exit" or command == "e":                                         # e or exit
            utils.dbgPrint("\n[*] Closing processes, files, and exiting.\n", Fore.GREEN)
            if self.variables["logging"] is True:
                utils.dbgLogFileClose()
            exit()
        elif command == "?p" or command == "?print":                                      # ?p or ?print
            self.printHelp()
        elif command == "?b" or command == "?breakpoint":                                 # ?b or ?breakpoint
            self.breakpointHelp()
        elif splitCommand[0][0] == "b" or splitCommand[0][:5] == "break":                 # b* or break*
            self.breakpointParse(command)
        elif splitCommand[0] == 'r' or splitCommand[0] == "run":                          # r or run
            if self.fileMode is True:
                dbg.enableFileMode()
            dbg.run()
        elif splitCommand[0] == 'c' or splitCommand[0] == "continue":                     # c or continue
            dbg.continueRunning()
            return DBG_CONTINUE
        elif splitCommand[0] == 'd' or splitCommand[0] == "detach":                       # d or detach
            dbg.detach()
            self.processName = dbg.processName
        elif splitCommand[0] == 'wa' or splitCommand[0] == "write_adr":                   # wa or write_adr
            dbg.writeMemory(command)
        elif splitCommand[0] == 'fr' or splitCommand[0] == "resolve":                     # fr or resolve
            if len(splitCommand) < 3:
                utils.dbgPrint("\n[-] Improper arguments. See help with ?.\n", Fore.RED)
                return
            dbg.getDllFunctionAddress(splitCommand[1], splitCommand[2])
        elif splitCommand[0] == "a" or splitCommand[0] == "attach":                       # a or attach
            if len(splitCommand) > 1:
                self.attach(splitCommand[1])
                self.processName = dbg.processName
                return True
            elif self.variables["pid"] is not 0:               # if the pid variable is set then no argument is needed
                self.attach(self.variables["pid"])
                self.processName = dbg.processName
                return True
            else:
                utils.dbgPrint("\n[-] Provide a PID to attach to.\n", Fore.RED)
                return False
        elif splitCommand[0] == "o" or splitCommand[0] == "open":                         # o or open
            if len(splitCommand) > 1:
                self.openAndAttach(splitCommand[1])
                return True
            elif self.variables["executable"] is not None:
                self.openAndAttach(splitCommand[1])
                return True
            else:
                utils.dbgPrint("\n[-] Provide a path to an executable to launch.\n", Fore.RED)
                return False
        elif splitCommand[0] == 'dc' or splitCommand[0] == "dump_context":                 # dc or dump_context
            dbg.dumpContext()
        elif splitCommand[0] == 'ds' or splitCommand[0] == "dump_seh":                     # ds or dump_seh
            dbg.dumpSEH()
        elif splitCommand[0] == 'dt' or splitCommand[0] == "dump_stack":                   # dt or dump_stack
            dbg.dumpStack()
        elif splitCommand[0] == 'sc' or splitCommand[0] == "snapshot_create":              # sc or snapshot_create
            dbg.createSnapshot()
        elif splitCommand[0] == 'sr' or splitCommand[0] == "snapshot_restore":             # sr or snapshot_restore
            dbg.restoreSnapshot()
        elif splitCommand[0] == 'sr' or splitCommand[0] == "set_reg":                      # sr or set_register
            if len(splitCommand) < 3:
                utils.dbgPrint("[-] Not enough args supplied.")
                return False
            elif len(splitCommand) == 3:
                dbg.setRegister(splitCommand[1].upper(), int(splitCommand[2], 0))
            else:
                dbg.setRegister(splitCommand[1].upper(), int(splitCommand[2], 0), int(splitCommand[3]))
        elif splitCommand[0] == 'id' or splitCommand[0] == "inject_dll":                  # id or inject_dll
            if len(splitCommand) != 3:
                utils.dbgPrint("\n[-] Improper args supplied.", Fore.RED)
                return False
            dbg.dllInject(int(splitCommand[1]), splitCommand[2])
        elif splitCommand[0] == 'is' or splitCommand[0] == "inject_shellcode":            # is or inject_shellcode
            if len(splitCommand) != 2:
                utils.dbgPrint("\n[-] Improper args supplied.", Fore.RED)
                return False
            dbg.shellcodeInject(int(splitCommand[1]))
        elif splitCommand[0] == 'di' or splitCommand[0] == "dump_info":                   # di or dump_info
            dbg.dumpInfo(command)
        elif splitCommand[0] == 'cm' or splitCommand[0] == "command":                     # cm or command
            utils.dbgPrint("")
            command = " ".join(splitCommand[1:])
            utils.dbgPrint("[DEBUG] Command: %s" % command, Fore.GREEN, verbose=self.debug)
            try:
                output = check_output(command.split(), shell=True)
            except:                 # Could not find command
                output = ""
            utils.dbgPrint(output)
        else:
            self.seeHelp()                                                                # incorrect command entered

    # Parse commands that begin with 'p' or 'print'
    def printParse(self, command):
        command = command.split()
        if command[0] == 'pv' or command[0] == 'print_var':                                     # Print variable
            if len(command) is 1:
                utils.dbgPrint("\n[-] Invalid variable name.\n", Fore.RED)
                return False
            input = command[1].lower()
            variable = self.checkVariable(input)
            if variable is not None:
                utils.dbgPrint("\n[*] %s = " % input, Fore.GREEN, secondLine="%s\n" % variable)
            else:
                utils.dbgPrint("\n[-] Invalid variable name.\n", Fore.RED)
        elif command[0] == 'pr' or command[0] == 'print_register':                              # Print register
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
                hexRegister = "%08x" % value
                utils.dbgPrint("\n[*] (Thread: %d) %s: 0x%08x, - Decimal: %d, ASCII: %s" % (thread, register, value, value, hexRegister.strip().decode("hex)")), Fore.GREEN)
        elif command[0] == "pa" or command[0] == "print_adr":                                # Print memory
            address = command[1]
            length = command[2]
            dbg.readMemory(address, length)
        else:
            utils.dbgPrint("[-] Print parser error.", Fore.RED)

    # Parse commands starting with 'b' or 'break' for breakpoint commands
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

    # Handler for when a breakpoint is hit
    def breakpointCommandHandler(self, dbgInstance):
        status = None
        while status != DBG_CONTINUE:
            status = self.runCommand(raw_input(utils.dbgPrint("\n[%s]> " % self.processName, Fore.GREEN, inputLine=True)))
        return DBG_CONTINUE

    # Check if a variable the user provides is a variable that can be set from the debugger command line
    def checkVariable(self, variable):
        if variable in self.variables.keys():
            output = self.variables[variable]
        else:
            output = None
        return output

    # Parse 's' or 'set' for setting variable and performing the necessary action.
    def variableParse(self, command):
        command = command.split()
        if len(command) < 3:
            utils.dbgPrint("\n[-] Incorrect usage, it should be \'set VARIABLE VALUE\'\n", Fore.RED)
            return False
        input_var = command[1].lower().strip()
        value = command[2].strip()
        if input_var in self.variables:
            if input_var == "logfile":                                                      # Logfile
                if ".txt" in value:
                    self.variables[input_var] = value
                    utils.dbgPrint("\n%s = %s\n" % (input_var, str(self.variables[input_var])))
                    self.variableParse("set logging true")
                    return
                else:
                    utils.dbgPrint("\n[-] Must be a .txt file\n", Fore.RED)
                    return
            elif input_var == "pid":                                                        # PID
                self.variables[input_var] = int(value)
            elif input_var == "verbose":                                                    # Verbose
                if value.lower() == "true":
                    self.variables[input_var] = True
                    dbg.setVerbose(True)
                elif value.lower() == "false":
                    self.variables[input_var] = False
                    dbg.setVerbose(False)
                else:
                    utils.dbgPrint("\n[-] Incorrect variable value given\n", Fore.RED)
                    return
            elif input_var == "debug":                                                    # Debug
                if value.lower() == "true":
                    self.variables[input_var] = True
                    self.debug = True
                    dbg.setDebug(True)
                elif value.lower() == "false":
                    self.variables[input_var] = False
                    self.debug = False
                    dbg.setDebug(False)
                else:
                    utils.dbgPrint("\n[-] Incorrect variable value given\n", Fore.RED)
                    return
            elif input_var == "crash-mode":                                                # Crash Mode
                if value.lower() == "true":
                    self.variables[input_var] = True
                    dbg.enableCrashMode()
                elif value.lower() == "false":
                    self.variables[input_var] = False
                    dbg.disableCrashMode()
                else:
                    utils.dbgPrint("\n[-] Incorrect variable value given\n", Fore.RED)
                    return
            elif input_var == "file-mode":                                                  # File Mode
                if value.lower() == "true":
                    self.variables[input_var] = True
                    self.fileMode = True
                elif value.lower() == "false":
                    self.variables[input_var] = False
                    self.fileMode = False
                    dbg.disableFileMode()
                else:
                    utils.dbgPrint("\n[-] Incorrect variable value given\n", Fore.RED)
                    return
            elif input_var == "hide-debugger":                                              # Hide debugger
                if value.lower() == "true":
                    self.variables[input_var] = True
                    dbg.enableHidden()
                elif value.lower() == "false":
                    self.variables[input_var] = False
                    dbg.disableHidden()
                else:
                    utils.dbgPrint("\n[-] Incorrect variable value given\n", Fore.RED)
                    return
            elif input_var == "logging":                                                    # Logging
                if value.lower() == "true":
                    self.variables[input_var] = True
                    utils.logging = True
                    utils.dbgLogFileCreate(self.variables["logfile"])
                elif value.lower() == "false":
                    self.variables[input_var] = False
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
        utils.dbgPrint("\n[DEBUG] %s = %s\n" % (input_var, str(self.variables[input_var])), verbose=self.debug)
        return True

    # Check if a PID is valid and attach to it
    # TODO move checks to debegger.py
    def attach(self, pid):
        if not isinstance(int(pid), (int, long)):
            utils.dbgPrint("\n[-] Invalid PID given\n", Fore.RED)
            return False
        self.variables["pid"] = int(pid)
        utils.dbgPrint("\n[*] Attempting to attach to PID %d\n" % int(pid), Fore.GREEN)
        dbg.attachPID(int(pid))
        return True

    # Open an executable
    def openAndAttach(self, path):
        utils.dbgPrint("\n[*] Opening %s\n" % path, Fore.GREEN)
        if os.path.exists(path) is True:
            self.processName = path.split("\\")[-1]
            dbg.loadExecutable(path, self.processName)
            return True
        else:
            utils.dbgPrint("\n[-] Error: Executable not found.\n", Fore.RED)

    # Start the tools
    def startProcessMonitor(self):
        dbgTools = tools.Tools(self.debug, self.variables['verbose'])
        utils.dbgPrint("\n[*] Starting process monitor...", Fore.GREEN)
        utils.dbgPrint("\n[*] Press Ctrl-C once and wait a few seconds to kill the process monitor...", Fore.GREEN)
        dbgTools.processMonitor()

    def startFileMonitor(self, command):
        dbgTools = tools.Tools(self.debug, self.variables['verbose'])
        utils.dbgPrint("\n[*] Starting file monitor...", Fore.GREEN)
        utils.dbgPrint("\n[*] Press Ctrl-C once and wait for another exception to get caught, then the tool will exit cleanly.", Fore.GREEN)
        dbgTools.fileMonitor(command)
