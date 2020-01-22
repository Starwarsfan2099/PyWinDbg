# pywindbg.py
# Created by Starwarsfan2099 on 4/22/2019

import argparse

from colorama import Fore

import commandParse
import utilities


version = "0.9"
utils = utilities.Utilities()

utils.dbgPrint("", Fore.GREEN)
utils.dbgPrint("PyWinDbg", Fore.GREEN)
utils.dbgPrint("Version %s" % version)
utils.dbgPrint("by Starwarsfan2099\n")

# Add all our command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pid", type=int, help="process PID to attach to.")
parser.add_argument("-o", "--open", type=str, help="executable to launch and attach to.")
parser.add_argument("-l", "--log", type=str, help="log file to log to.")
parser.add_argument("-v", "--verbose", help="print more information.", action="store_true")
parser.add_argument("-d", "--debug", help="gives debugging information for development and bug hunting.", action="store_true")
parser.add_argument("-x", "--hide", help="hides debugger from debugee when first breakpoint is hit.", action="store_true")
parser.add_argument("-c", "--crash_mode", help="places hooks and prints information when a process crashes.", action="store_true")
parser.add_argument("-f", "--file_mode", help="hooks file creation and modification functions, printing info when called.", action="store_true")
parser.add_argument("-pm", "--process_monitor", help="starts monitoring all created processes.", action="store_true")
parser.add_argument("-fm", "--file_monitor", help="monitors file modification, creation, and deletion.", action="store_true")
args = parser.parse_args()
parser = commandParse.Parser()

# Parse the command line arguments given, if any
if args.log is not None:                                            # Log file
    parser.variables["logfile"] = args.log
    parser.variableParse("set logging True")
    utils.dbgPrint("[*] Logfile = %s" % args.log, Fore.GREEN)
if args.open is not None:                                           # Opening a file from command line
    parser.openAndAttach(args.open)
if args.verbose is True:                                            # Verbose mode
    parser.variables["verbose"] = True
    parser.variableParse("set verbose True")
    utils.dbgPrint("[*] Verbose = True", Fore.GREEN)
if args.debug is True:                                              # Debug mode
    parser.variables["debug"] = True
    parser.variableParse("set debug True")
    utils.dbgPrint("[*] Debug = True", Fore.GREEN)
if args.hide is True:                                               # Hide debugger
    parser.variables["hide-debugger"] = True
    parser.variableParse("set hide-debugger True")
    utils.dbgPrint("[*] Hide-debugger = True", Fore.GREEN)
if args.crash_mode is True:                                         # Crash Mode
    parser.variables["crash-mode"] = True
    parser.variableParse("set crash-mode True")
    utils.dbgPrint("[*] Crash-mode = True", Fore.GREEN)
if args.file_mode is True:                                          # File Mode
    parser.variables["file-mode"] = True
    parser.variableParse("set file-mode True")
    utils.dbgPrint("[*] File-mode = True", Fore.GREEN)
if args.process_monitor is True:                                    # Process monitor
    parser.startProcessMonitor()
if args.file_monitor is True:                                       # File monitor
    parser.startFileMonitor("fm")

utils.dbgPrint("")

# Start the main command prompt loop
if __name__ == '__main__':
    while True:
        parser.runCommand(raw_input(utils.dbgPrint("[%s]> " % parser.processName, Fore.GREEN, inputLine=True)))
