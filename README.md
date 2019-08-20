# PyWinDbg
PyWinDbg is a basic command line Windows debugger written in Python for learning purposes.
It currently supports loading an executable, attaching to a process, setting breakpoints, modifying and viewing registers, hooking `Win32` file creation functions, catching and detecting the cause of crashes, dll injection, process monitoring, file monitoring, and executable information dumping.
 
# Overview of Functions:
## Commands:

````
PyWinDbg
Version 0.8
by Starwarsfan2099


[pywindbg]> ?

 Commands:
 p* | print stuff                   Prints stuff. Use ?p for more help.
 e  | exit                          Exits the debugger and closes the process if active.
 cl | clear                         Clear the console.
 s  | set VARIABLE VALUE            Set a variable.
 ?  | help                          This help menu.


 a  | attach PID                    Attach to a process ID.
 d  | detach                        Detach from a process.
 l  | list NAME|PID                 List current PID's, or search one by name or PID.
 o  | open EXE                      Launch and attach to an executable.
 r  | run ARGS                      Starts the opened process with args.
 c  | continue                      Continue execution after hitting a breakpoint.
 b* | set breakpoints               Setting breakpoints. Use ?b for more help.
 fr | resolve FUNC LIB              Returns the address for a function from a dll.
 dc | dump_context                  Returns current EIP disassembled and stack unwind.
 di | dump_info EXE|DLL|PID         Return information on PID, or debugging EXE, or supplied DLL.
 sr | set_reg REG VAL ID            Sets register REG to VAL in thread ID, all threads if no ID is specified.
 id | inject_dll PID DLL            Injects DLL into process PID.
 is | inject_shellcode PID          Injects sellcode from the shellcode.py file into process PID.
 wa | write_adr ADD LEN DATA        Writes data to an address.


Tools:
 pm | process_monitor               Starts monitoring all created processes.
 fm | file_monitor DIR              Monitors file modification, creation, and deletion within DIR.


 Variables:
      verbose | True|False          Enables more output.
      debug   | True|False          Enables debugging output for development and bug hunting.
      logging | True|False          Enable logging to FILE.
      logfile | FILE.txt            Text file to log to, must be .txt.
   crash-mode | True|False          Enables crash mode.
    file-mode | True|False          Enables file hooking mode.
hide-debugger | True|False          Hide the debugger after first breakpoint.


 More help:
 ?p | ?print                        Print methods help.
 ?b | ?breakpoint                   Breakpoint methods help.
````

## Command line options:
````
PyWinDbg
Version 0.8
by Starwarsfan2099

usage: pywindbg.py [-h] [-p PID] [-o OPEN] [-l LOG] [-v] [-d] [-x] [-c] [-f]
                   [-pm] [-fm]

optional arguments:
  -h, --help            show this help message and exit
  -p PID, --pid PID     process PID to attach to.
  -o OPEN, --open OPEN  executable to launch and attach to.
  -l LOG, --log LOG     log file to log to.
  -v, --verbose         print more information.
  -d, --debug           gives debugging information for development and bug
                        hunting.
  -x, --hide            hides debugger from debugee when first breakpoint is
                        hit.
  -c, --crash_mode      places hooks and prints information when a process
                        crashes.
  -f, --file_mode       hooks file creation and modification functions,
                        printing info when called.
  -pm, --process_monitor
                        starts monitoring all created processes.
  -fm, --file_monitor   monitors file modification, creation, and deletion.
  ````

## Loading a process to debug
Attaching to a process can be done from the prompt with `attach PID`. Every command has a shortened version, for `attach`, the other command is `a`, so `a EXE` can be used as well. Or from the command line with `-p PID`.
If the PID is not known, `list` or `l` will print all running processes and PIDs or `l NAME` will search for a process name.
To open an executable and run it, from the prompt `o EXE` or `open EXE`, or use `-o EXE` from the command line.
Once a process is loaded or attached, `r` or `run` will launch the process.
Variables can be used to enable certain options such as verbose or use different modes.
Variables can be set with `s VARIABLE VALUE` or `set VARIABLE VALUE`.
Variables can be viewed with `pv VARIABLE` or `print_variable VARIABLE`.

## Breakpoints
![Setting a breakpoint](https://github.com/Starwarsfan2099/PyWinDbg/blob/master/Screenshots/setting_breakpoint.png)
To set a breakpoint, a function address can be resolved with `function_resolve FUNCTION LIBRARY` (or `fr`) and the address can be set as a breakpoint with `break ADDRESS` (`b`).
Or it can be automatically set with `break_funk FUNCTION LIBRARY` (`bf`).
When a breakpoint is hit, the prompt will return so commands can be run.

`Note: Images may be different from the current versions output due to updates and changes.`

## When a breakpoint is hit
![Printing registers](https://github.com/Starwarsfan2099/PyWinDbg/blob/master/Screenshots/print_registers.png)
`print_reg` or `pr` will print all registers. 
`pr REGISTER` will print only that specific register.
`set_reg REGISTER VALUE` or `sr REGISTER VALUE` sets a specified register to that value.

![Dump context](https://github.com/Starwarsfan2099/PyWinDbg/blob/master/Screenshots/dump_context.png)
`dc` or `dump_context` will print information from the current registers, color coding what they point to.

`c` or `continue` will continue debugging until the next breakpoint is hit.

## Crash mode
![Crash mode](https://github.com/Starwarsfan2099/PyWinDbg/blob/master/Screenshots/crash_mode.png)
Crash mode detects `exception_debug_event`, determines the cause of the crash, and prints lots of useful output.
This can be enabled from the prompt via the variables with `set crash-mode true` or via the command line options with `-c`.

## Created Files Mode
![File hooking mode](https://github.com/Starwarsfan2099/PyWinDbg/blob/master/Screenshots/file_mode.png)
Hooks several Windows functions and prints any files made, deleted, or modified.
Enabled with `set file-mode true` or from the command line options with `-f`.

## DLL injection
![DLL injection](https://github.com/Starwarsfan2099/PyWinDbg/blob/master/Screenshots/dll_inject.png)
`inject_dll PID DLL` (`id`) will attempt to inject the specified dll into the specified process PID.
You must have proper privileges and be injecting to a same bit process.

## Shellcode injection
![Shellcode injection](https://github.com/Starwarsfan2099/PyWinDbg/blob/master/Screenshots/shellcode_inject.png)
`inject_shellcod PID` or `is PID` will inject the shellcode from shellcode.py stored in the variable `shellcode`
By default the shellcode is a simple Windows message box.

## Writing and Reading memory
Reading memory can be performed with `pa ADDRESS LENGTH` or `print_adr`.
Writing memory can be done with `write_adr ADDRESS LENGTH DATA` (`wa`).


## Tools
### File monitor
![File monitoring mode](https://github.com/Starwarsfan2099/PyWinDbg/blob/master/Screenshots/file_monitor.png)
File monitoring works different from the file hooking mode, in that it monitors a directory for file creation, modification, and deletion.
It will also attempt to dump the contents of the file.
The tool can be used with `file_monitor` (`fm`) or from the command line with `-fm`.
By default it monitors Windows temp directories, but a specific directory can be passed with `file_monitor DIR`.

### Process monitor

![Process monitor mode](https://github.com/Starwarsfan2099/PyWinDbg/blob/master/Screenshots/process_monitor.png)
The Process monitor tool prints information for processes started or stopped.
Launched with `process_monitor` (`pm`) or from the command line options with `-pm`.

### Dumping process or executable info

`di` or `dump_info` can be used to dump information on the currently attached process if no arguments are passed.
If a PID is passed, it will dump the some information.
If an executable or DLL is passed, it will dump the headers, sections, architecture information, and more.

![Dumping process information](https://github.com/Starwarsfan2099/PyWinDbg/blob/master/Screenshots/dump_info_3.png)
![Dumping exe information](https://github.com/Starwarsfan2099/PyWinDbg/blob/master/Screenshots/dump_info_1.png)
![More exe information](https://github.com/Starwarsfan2099/PyWinDbg/blob/master/Screenshots/dump_info_2.png)

## Other notes

### Executables

`pywindbg.exe`: Standalone portable executable version of PyWinDbg.

`bufferOverflow.exe`: Program that has a purposeful buffer overflow for testing the debugger.

`helloDLL.dll`: DLL for injection that simply creates a popup window.

### Command line options
`-v`: Verbose mode

`-l FILE`: Log all output to a file.

`-d`: Enable some debug printing for development.

`-x`: Hide the debugger after the first breakpoint.

### Other Files
`build_pywindbg.bat`: Script to build an executable using pyinstaller.

`build_buffer_overflow.bat`: Script to build an executable for `bufferOverflow.py` using pyinstaller.

`build_dll.bat`: Script to build the `helloDLL.dll` included for injection. It must be ran from the Visual Studio Developer Command Prompt.

`helloDLL.cpp`: Source for the compiled DLL included.

`stdfax.h` and `tagetver.h`: Headers for the DLL.

`bufferOverflow.py`: Source for the compiled `bufferOverflow.exe` file included.

`shellcode.py`: File that PyWinDbg imports shellcode from for injection into a process.

Note: `build_pywindbg.bat` and `build_buffer_overflow.bat` use my local install of upx, you'll probably have to change the path or remove the upx option.

## TODO

- ~~Add memory reading/writing.~~
- ~~Print register and contents in different formats.~~
- ~~Add shellcode injection.~~
- Dump SEH after breakpoint is hit.
- Memory and hardware breakpoints.

## Dependencies

- pefile
- psutil
- win32con
- win32api
- win32security
- win32file
- wmi
- pythoncom
- tempfile
- colorama
- argparse
- cPickle