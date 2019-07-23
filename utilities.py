# utilities.py
# Created by Starwarsfan2099 on 4/22/19

from colorama import init, Fore, Style

init(autoreset=True)

N_A_color = Fore.RED
heap_color = Fore.YELLOW
stack_color = Fore.CYAN

class Utilities:
    __instance = None

    @staticmethod                                           # We need one single instance of this class shared across
    def getInstance():                                      # several modules.
        """ Static access method. """
        if Utilities.__instance == None:
            Utilities()
        return Utilities.__instance

    def __init__(self):
        self.logfileName = "log.txt"
        self.logging = False
        self.log = None
        Utilities.__instance = self

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


    def dbgLogFileWrite(self, line):
        self.log.write(line + "\n")

    def dbgLogFileClose(self):
        self.log.close()

    def dbgLogFileCreate(self, fileName):
        self.logfileName = fileName
        self.log = open(fileName, "w+")
        self.log.write("PyWinDbg\nBy Starwarsfan2099\nLog file:\n")
