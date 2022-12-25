import textwrap
import frida
import os
import sys
import frida.core
import argparse
import logging
import utils
import dumper

#Dex 2022
#Based on https://github.com/Nightbringer21/fridump and https://github.com/azurda/frida-dump

logo = """
  ____       _   _            _____                        
 |  _ \\     | | | |          |  __ \\                       
 | |_) | ___| |_| |_ ___ _ __| |  | |_   _ _ __ ___  _ __  
 |  _ < / _ \\ __| __/ _ \\ '__| |  | | | | | '_ ` _ \\| '_ \\ 
 | |_) |  __/ |_| ||  __/ |  | |__| | |_| | | | | | | |_) |
 |____/ \\___|\\__|\\__\\___|_|  |_____/ \\__,_|_| |_| |_| .__/ 
                                                    | |    
                                                    |_|    
        """

def bytesToFile(name, directory, data):
        try:
                filename = str(name)+'_dump.data'
                dump =  agent.read_memory(base, size)
                f = open(os.path.join(directory,filename), 'wb')
                f.write(data)
                f.close()
                return True
        except Exception as e:
            logging.debug("[!]"+str(e))
            print("Failed to write " + str(filename) + "!")
            return False

# Main Menu
def MENU():
    parser = argparse.ArgumentParser(
        prog='fridump',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(""))

    parser.add_argument('process',
                        help='the process PID that you will be injecting to')
    parser.add_argument('-o', '--out', type=str, metavar="dir",
                        help='provide full output directory path. (def: \'dump\')')
    parser.add_argument('-U', '--usb', action='store_true',
                        help='device connected over usb')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose')
    parser.add_argument('-r', '--read-only', action='store_true',
                        help="dump read-only parts of memory. More data, more errors")
    parser.add_argument('-m', '--modules', action='store_true',
                        help="extract a list of modules and their base addresses from the app")
    parser.add_argument('-s', '--strings', action='store_true',
                        help='run strings on all dump files. Saved in output dir.')
    parser.add_argument('--max-size', type=int, metavar="bytes",
                        help='maximum size of dump file in bytes (def: 20971520)')
    args = parser.parse_args()
    return args


print(logo)

arguments = MENU()

if (not str(arguments.process).isnumeric()):
    print("Process PID must be numeric!")
    logging.debug(str(arguments.process) + " is not a valid PID")
    sys.exit()

# Define Configurations
#APP_NAME = arguments.process
APP_PID = int(arguments.process)
DIRECTORY = ""
USB = arguments.usb
MODULES = arguments.modules
DEBUG_LEVEL = logging.INFO
STRINGS = arguments.strings
MAX_SIZE = 20971520
PERMS = 'rw-'

if arguments.read_only:
    PERMS = 'r--'

if arguments.verbose:
    DEBUG_LEVEL = logging.DEBUG
logging.basicConfig(format='%(levelname)s:%(message)s', level=DEBUG_LEVEL)


# Start a new Session
session = None
try:
    if USB:
        session = frida.get_usb_device().attach(APP_PID) #APP_NAME
    else:
        session = frida.attach(APP_PID) #APP_NAME
except Exception as e:
    print("Can't connect to App. Have you connected the device?")
    logging.debug(str(e))
    sys.exit()

# Selecting Output directory
if arguments.out is not None:
    DIRECTORY = arguments.out
    if os.path.isdir(DIRECTORY):
        print("Output directory is set to: " + DIRECTORY)
    else:
        print("The selected output directory does not exist!")
        sys.exit(1)

else:
    print("Current Directory: " + str(os.getcwd()))
    DIRECTORY = os.path.join(os.getcwd(), "dump")
    print("Output directory is set to: " + DIRECTORY)
    if not os.path.exists(DIRECTORY):
        print("Creating directory...")
        os.makedirs(DIRECTORY)

print("Starting Memory dump...")

#Load frida script
script = None
with open("script.js") as jsfile:
    script = session.create_script(jsfile.read())

if (not script):
    print("Missing script.js, terminating!")
    exit()

#Load script
script.on("message", utils.on_message)
script.load()
agent = script.exports

if MODULES:
    #Write info about modules in memory
    loaded_modules = agent.enumerate_modules()
    main_module = loaded_modules[0]
    print(repr(main_module))
    print("Extracting module data...")
    modules_path = os.path.join(DIRECTORY,'modules.txt')
    with open(modules_path, 'w') as f:
        f.write(repr(loaded_modules))

mem_access_viol = ""
ranges = agent.enumerate_ranges(PERMS)

if arguments.max_size is not None:
    MAX_SIZE = arguments.max_size

# Performing the memory dump
i = 0
l = len(ranges)
for range in ranges:
    base = range["base"]
    size = range["size"]

    logging.debug("Base Address: " + str(base))
    logging.debug("Size: " + str(size))

    if size > MAX_SIZE:
        logging.debug("Too big, splitting the dump into chunks")
        mem_access_viol = dumper.splitter(agent, base, size, MAX_SIZE, mem_access_viol, DIRECTORY)
        continue

    mem_access_viol = dumper.dump_to_file(agent, base, size, mem_access_viol, DIRECTORY)
    i += 1
    utils.printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)

# Run Strings if selected
if STRINGS:
    files = os.listdir(DIRECTORY)
    i = 0
    l = len(files)
    print("Running strings on all files:")
    for f1 in files:
        utils.strings(f1, DIRECTORY)
        i += 1
        utils.printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)

print("Finished!")
exit()


"""
#Currently broken WIP
#Collect memory data
memory = agent.dump_process_memory(PERMS)
mem_names = memory[0]
mem_data = memory[1]

#Dump to files
print("Dumping " + str(len(mem_names)) + " memory regions...")

nonempty = 0
for name, data in zip(mem_names, mem_data):
    nameStr = str(name) + ".mem"
    if (len(data) > 0):
        bytesToFile(nameStr, DIRECTORY, data)
        nonempty += 1
    else:
        print(nameStr + " is empty, skipping...")

    i += 1
    utils.printProgress(i, len(mem_names), prefix='Progress:', suffix='Complete', bar=50)

print("Dumped " + str(nonempty) + " non-empty memory regions. Dumping finished!")
"""