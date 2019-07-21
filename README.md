# PyWinDbg
PyWinDbg is a command line is a basic Windows debugger written in Python for learning purposes.
It currently supports loading an executable, attaching to a process, setting breakpoints, modifying and viewing registers, hooking `Win32` file creation functions, catching and detecting the cause of crashes, dll injection, process monitoring, and file monitoring.
 
# Overview of Functions:
## Commands:

````
PyWinDbg
Version 0.1
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
 sr | set_register REG VAL ID       Sets register REG to VAL in thread ID, all threads if no ID is specified.
 id | inject_dll PID DLL            Injects DLL into Process PID.


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
hide-debugger | True|False          Enables file hooking mode.


 More help:
 ?p | ?print                        Print methods help.
 ?b | ?breakpoint                   Breakpoint methods help.


[pywindbg]>
````

## Command line options:
````
PyWinDbg
Version 0.1
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
![Setting a breakpoint](screenshots/setting_breakpoint.png)
To set a breakpoint, a function address can be resolved with `function_resolve FUNCTION LIBRARY` (or `fr`) and the address can be set as a breakpoint with `break ADDRESS` (`b`).
Or it can be automatically set with `break_funk FUNCTION LIBRARY` (`bf`).
When a breakpoint is hit, the prompt will return so commands can be run.

## When a breakpoint is hit
![Printing registers](screenshots/print_registers.png)
`print_reg` or `pr` will print all registers. 
`pr REGISTER` will print only that specific register.
`set_reg REGISTER VALUE` or `sr REGISTER VALUE` sets a specified register to that value.

![Dump context](screenshots/dump_context.png)
`dc` or `dump_context` will print information from the current registers, color coding what they point to.

`c` or `continue` will continue debugging until the next breakpoint is hit.

## Crash mode
![Crash mode](screenshots/crash_mode.png)
Crash mode detects `exception_debug_event`, determines the cause of the crash, and prints lots of useful output.
This can be enabled from the prompt via the variables with `set crash-mode true` or via the command line options with `-c`.

## Created Files Mode
![File hooking mode](screenshots/file_mode.png)
Hooks several Windows functions and prints any files made, deleted, or modified.
Enabled with `set file-mode true` or from the command line options with `-f`.

## DLL injection
![DLL injection](screenshots/dll_inject.png)
`inject_dll PID DLL` (`id`) will attempt to inject the specified dll into the specified process PID.
You must have proper privileges and be injecting to a same bit process.

## Tools
### File monitor
![File monitoring mode](screenshots/file_monitor.png)
File monitoring works different from the file hooking mode, in that it monitors a directory for file creation, modification, and deletion.
It will also attempt to dump the contents of the file.
The tool can be used with `file_monitor` (`fm`) or from the command line with `-fm`.
By default it monitors Windows temp directories, but a specific directory can be passed with `file_monitor DIR`.

### Process monitor

![Process monitor mode](screenshots/process_monitor.png)
The Process monitor tool prints information for processes started or stopped.
Launched with `process_monitor` (`pm`) or from the command line options with `-pm`.

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

## TODO

- Add memory reading/writing.
- Print register and contents in different formats.
- Add shellcode injection.
- Dump SEH after breakpoint is hit.
- Memory and hardware breakpoints.