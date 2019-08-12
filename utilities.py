# utilities.py
# Created by Starwarsfan2099 on 4/22/19

from colorama import init, Fore, Style
import datetime

init(autoreset=True)

N_A_color = Fore.RED
heap_color = Fore.YELLOW
stack_color = Fore.CYAN

currentTime = datetime.datetime.now()

class Utilities:
    __instance = None

    @staticmethod                                           # We need one single instance of this class shared across
    def getInstance():                                      # several modules.
        """ Static access method. """
        if Utilities.__instance is None:
            Utilities()
        return Utilities.__instance

    def __init__(self):
        self.logfileName = "log-%s.txt" % currentTime.strftime("%Y-%m-%d-%H-%M")
        self.logging = False
        self.log = None
        Utilities.__instance = self

    # Our print function for coloring output and saving lines to the log
    def dbgPrint(self, output, attribute=None, inputLine=False, verbose=True, dualline=False, secondline=""):
        if verbose is not False:
            if attribute is None:
                line = output
            else:
                if dualline is False:
                    line = '\033[1m' + attribute + output
                else:
                    line = '\033[1m' + attribute + output + '\033[1m' + Style.RESET_ALL + secondline
            if inputLine is not False:
                return line
            else:
                print line
                if self.logging is True:
                    if dualline is False:
                        self.dbgLogFileWrite(output)
                    else:
                        self.dbgLogFileWrite(output + secondline)

    # File logging functions
    def dbgLogFileWrite(self, line):
        self.log.write(line + "\n")

    def dbgLogFileClose(self):
        self.log.close()

    def dbgLogFileCreate(self, fileName):
        self.logfileName = fileName
        self.log = open(fileName, "w+")
        self.log.write("PyWinDbg\nBy Starwarsfan2099\nLog file:\n")

    def toHex(self, s):
        lst = []
        for ch in s:
            hv = hex(ord(ch)).replace('0x', '')
            if len(hv) == 1:
                hv = '0' + hv
            lst.append(hv)

        return reduce(lambda x, y: x + y, lst)

    # convert hex repr to string
    def toStr(self, s):
        return s and chr(atoi(s[:2], base=16)) + toStr(s[2:]) or ''
