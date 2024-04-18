#!/usr/bin/env python3

import subprocess
import argparse
import yara
import os
import magic
import re
from colorama import Fore, Style

# Define globals
global pathToSample

version = "1.0.2"

def runFloss(file_path):
    printHeader("FLOSS", file_path)
    try:
        subprocess.call(["floss", file_path, "-o", file_path+"_Output/floss.txt"])
    except Exception as e:
        print(f"{Fore.RED}[*] ERROR: {Style.RESET_ALL}An error occurred in FLOSS: {e}")

def runB64Dump(file_path):
    printHeader("base64dump", file_path)
    try:
        result = subprocess.run(["base64dump.py", file_path], capture_output=True, text=True)
        print(f"{result.stdout}")
        with open(f"{file_path}_Output/base64dump.txt", 'w') as f:
            f.write(result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[*] ERROR: {Style.RESET_ALL}An error occurred in base64dump: {e}")

def runDIE(file_path):
    printHeader("DetectItEasy", file_path)
    try:
        subprocess.call(["diec", "-S", "'File name'", file_path])
        result = subprocess.run(["diec", "-rd", file_path], capture_output=True, text=True)
        print(f"{result.stdout}")
        subprocess.call(["diec", "-S", "Size", file_path])
        subprocess.call(["diec", "-S", "Hash", file_path])
        subprocess.call(["diec", "-S", "Entropy", file_path])
        subprocess.call(["diec", "-S", "'File type'", file_path])
        if "Packer" in result.stdout:
            print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL} {file_path}is packed.")
            if "UPX" in result.stdout:
                print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL}UPX packing detected. Attempting to unpack..")
                runUPX(file_path)
    except Exception as e:
        print(f"{Fore.RED}[*] ERROR: {Style.RESET_ALL}An error occured in DIE: {e}")

def getYARARules():
    rules = []
    yaraErrors = []
    for root, _, files in os.walk('/usr/local/yara-rules'):
        for filename in files:
            if filename.endswith(".yar") or filename.endswith(".yara"):
                try:
                    rule_path = os.path.join(root, filename)
                    rule = yara.compile(filepath=rule_path)
                    rules.append(rule)
                except yara.Error as e:
                    yaraErrors.append(f"Error loading '{filename}': {e}")
    with open("yaraErrors.txt", 'w') as f:
        for error in yaraErrors:
            f.write(error + "\n")
    return rules

def runYARA(file_path, rules):
    printHeader("YARA", file_path)
    ruleCount = len(rules)
    print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL}Running {file_path} against {ruleCount} rules..")
    try:
        matches = []
        for rule in rules:
            result = rule.match(file_path)
            if result:
                matches.extend(result)
        if matches:
            print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL}{len(matches)} matches found.\n")
            for match in matches:
                print(match)
            with open(f"{file_path}_Output/yaraMatches.txt", 'w') as f:
                for match in matches:
                    f.write(str(match))
                    f.write("\n")
        else:
            print("No YARA matches found.")
            with open(f"{file_path}_Output/yaraMatches.txt", 'w') as f:
                f.write("No matches found.")
    except yara.Error as e:
        print(f"Error scanning file '{file_path}': {e}")

def runCapa(file_path):
    printHeader("Capa", file_path)
    try:
        result = subprocess.run(["capa", file_path], capture_output=True, text=True)
        print(f"{result.stdout}")
        with open(f"{file_path}_Output/capa.txt", 'w') as f:
            f.write(result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[*] ERROR: {Style.RESET_ALL}An error occurred in Capa: {e}")

def runPEFrame(file_path):
    printHeader("PEFrame", file_path)
    try:
        result = subprocess.run(["peframe", file_path], capture_output=True, text=True)
        print(f"{result.stdout}")
        with open(f"{file_path}_Output/peframe.txt", 'w') as f:
            f.write(result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[*] ERROR: {Style.RESET_ALL}An error occurred in PEFrame: {e}")

def runUPX(file_path):
    printHeader("UPX", file_path)
    try:
        subprocess.call(["upx", "-d", file_path, "-o", "unpacked_"+file_path])
        newFile = "unpacked_"+file_path
        if os.path.exists(newFile):
            print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL}New file written to {newFile}.")
            changeFocus = input(f"{Fore.YELLOW}INPUT REQUIRED:{Style.RESET_ALL} Do you want to change the target of analysis to the unpacked file instead? (y/n): ")
            if changeFocus.lower().startswith("y"):
                global pathToSample
                pathToSample = newFile
                prepDirectory(pathToSample)
                runDIE(pathToSample)
    except Exception as e:
        print(f"{Fore.RED}[*] ERROR: {Style.RESET_ALL}An error occurred in UPX: {e}")

def runSpeakeasy(file_path):
    printHeader("Speakeasy", file_path)
    try:
        subprocess.call(["speakeasy", "-t", file_path, "-d", file_path+"_Output/speakeasy_memdump", "-z", file_path+"_Output/dropped_files"])
    except Exception as e:
        print(f"{Fore.RED}[*] ERROR: {Style.RESET_ALL}An error occurred in Speakeasy: {e}")

def runCobaltStrikeMetadata(file_path):
    printHeader("Cobalt Strike Metadata Decryptor", file_path)
    try:
        result = subprocess.run(['cs-decrypt-metadata.py', file_path], capture_output=True, text=True)
        print(f"{result.stdout}")
        if result.stderr:
            print(f"{file_path} does not appear to be a Cobalt Strike beacon.")
        with open(f"{file_path}_Output/cobalt_strike_metadata.txt", 'w') as f:
            f.write(result.stdout)
            f.write(result.stderr)
    except:
        print(f"{file_path} does not appear to be a Cobalt Strike beacon.")

# Office Product Analysis Section
def runOLEID(file_path):
    printHeader("OLEID", file_path)
    try:
        result = subprocess.run(['oleid', file_path], capture_output=True, text=True)
        print(f"{result.stdout}")
        with open(f"{file_path}_Output/oleid.txt", 'w') as f:
            f.write(result.stdout)
            f.write(result.stderr)
        if "olevba" in result.stdout:
            print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL}VBA script detected. Dumping the script..")
            runOLEVBA(file_path)
        if "oleobj" in result.stdout:
            runOLEObj(file_path)
    except Exception as e:
        print(f"{Fore.RED}[*] ERROR: {Style.RESET_ALL}An error occurred in OLEID: {e}")

def runOLEVBA(file_path):
    printHeader("OLEVBA", file_path)
    try:
        result = subprocess.run(['olevba', file_path, '--decode'], capture_output=True, text=True)
        print(f"{result.stdout}")
        with open(f"{file_path}_Output/olevba.txt", 'w') as f:
            f.write(result.stdout)
            f.write(result.stderr)
    except Exception as e:
        print(f"{Fore.RED}[*] ERROR: {Style.RESET_ALL}An error occurred in OLEVBA: {e}")

def runOLEObj(file_path):
    printHeader("OLEObj", file_path)
    try:
        result = subprocess.run(['oleobj', file_path], capture_output=True, text=True)
        print(f"{result.stdout}")
        with open(f"{file_path}_Output/oleobj.txt", 'w') as f:
            f.write(result.stdout)
            f.write(result.stderr)
    except Exception as e:
        print(f"{Fore.RED}[*] ERROR: {Style.RESET_ALL}An error occurred in OLEObj: {e}")

def runOLEDump(file_path):
    printHeader("OLEDUMP", file_path)
    result = subprocess.run(['oledump.py', file_path], capture_output=True, text=True)
    if "Ole10Native" in result.stdout:
        pattern = r"(\w+):\s+O\s+\d+\s+'\\x01Ole10Native'"
        match = re.search(pattern, result.stdout)
        if match:
            print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL}OLE Object detected. Attempting to dump the object.")
            streamValue = match.group(1)
            result = subprocess.run(['oledump.py', '-s', streamValue, '--decompress', '-d', file_path], capture_output=True, text=False)
            result = result.stdout.decode('utf-8', errors='ignore')
            print(f"{result}\n")
            with open(f"{file_path}_Output/oleDumpedObject.txt", 'w') as f:
                f.write(result)

def runViperMonkey(file_path):
    printHeader("ViperMonkey", file_path)
    try:
        result = subprocess.run(['vmonkey', file_path], capture_output=True, text=True)
        print(f"{result.stdout}")
        with open(f"{file_path}_Output/vmonkey.txt", 'w') as f:
            f.write(result.stdout)
            f.write(result.stderr)
    except Exception as e:
        print(f"{Fore.RED}[*] ERROR: {Style.RESET_ALL}An error occurred in ViperMonkey: {e}")

def runPeepdf(file_path):
    printHeader("peepdf", file_path)
    try:
        result = subprocess.run(['peepdf', file_path], capture_output=True, text=True)
        print(f"{result.stdout}")
        with open(f"{file_path}_Output/peepdf.txt", 'w') as f:
            f.write(result.stdout)
            f.write(result.stderr)
        if "Objects" in result.stdout:
            pattern = r"Objects:\s*(\d+)"
            match = re.search(pattern, result.stdout)
            if match:
                pdfDirectory = f"{file_path}_Output/pdfDumpedObjects"
                numberOfObjects = int(match.group(1))
                print("")
                print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL}{numberOfObjects} objects found within PDF document. Dumping objects..\n")
                numbersList = [str(i) for i in range(1, numberOfObjects+1)]
                commaSeparatedNumbers = ",".join(numbersList)
                runPDFParser(file_path, commaSeparatedNumbers, pdfDirectory)
    except Exception as e:
        print(f"{Fore.RED}[*] ERROR: {Style.RESET_ALL}An error occurred in peepdf: {e}")

def runPDFParser(file_path, objects, directory):
    try:
        result = subprocess.run(['pdf-parser.py', '-f', "-o", objects, "-d", directory, file_path], capture_output=True, text=True) 
        print(f"{result.stdout}")
        with open(f"{file_path}_Output/pdfParser.txt", 'w') as f:
            f.write(result.stdout)
            f.write(result.stderr)
        print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL}Dumped objects found to {directory}")      
    except Exception as e:
        print(f"{Fore.RED}[*] ERROR: {Style.RESET_ALL}An error occurred in PDF-Parser: {e}")

# Metadata collection
def getFileType(file_path):
    magic_instance = magic.Magic()
    file_type = magic_instance.from_file(file_path)
    return file_type

def printHeader(functionName, file_path):
    print(f"{Fore.YELLOW}\n[----------------------------------------------------------------------------------------]")
    print(f"Starting {functionName} Analysis against {file_path}".center(90))
    print(f"[----------------------------------------------------------------------------------------]\n{Style.RESET_ALL}")

def prepDirectory(pathToSample):
    try:
        if not os.path.exists(pathToSample+"_Output"):
            os.makedirs(pathToSample+"_Output")
            print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL}Directory {pathToSample}_Output created.")
    except Exception as e:
        print(f"{Fore.RED}[*] ERROR: {Style.RESET_ALL}An error occurred: {e}")

def printBanner():
    print(f""" {Fore.YELLOW}                                                                                         
                          88           88                                                  
                          88           88                                                  
                          88           88                                                  
 ,adPPYb,d8   ,adPPYba,   88   ,adPPYb,88  ,adPPYba,   ,adPPYba,  ,adPPYYba,  8b,dPPYba,   
a8"    `Y88  a8"     "8a  88  a8"    `Y88  I8[    ""  a8"     ""  ""     `Y8  88P'   `"8a  
8b       88  8b       d8  88  8b       88   `"Y8ba,   8b          ,adPPPPP88  88       88  
"8a,   ,d88  "8a,   ,a8"  88  "8a,   ,d88  aa    ]8I  "8a,   ,aa  88,    ,88  88       88  
 `"YbbdP"Y8   `"YbbdP"'   88   `"8bbdP"Y8  `"YbbdP"'   `"Ybbd8"'  `"8bbdP"Y8  88       88  
 aa,    ,88                                                                                
  "Y8bbdP"                                                                                 
    """)
    print(f"{Style.RESET_ALL}-- Automate Your Analysis --".center(90))
    print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL}v{version}")

def main():
    parser = argparse.ArgumentParser(description="Static Analysis of Suspicious Files")
    parser.add_argument("file", help="Path to the file to be analyzed")
    args = parser.parse_args()
    global pathToSample
    pathToSample = args.file
    printBanner()
    prepDirectory(pathToSample)
    print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL}Loading rules..")
    yararules = getYARARules()
    fileType = getFileType(pathToSample)
    if "PDF" in fileType:
        print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL}PDF detected. Beginning analysis..")
        runYARA(pathToSample, yararules)
        runPeepdf(pathToSample)
    elif "Microsoft" in fileType:
        print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL}Office Document detected. Beginning analysis..")
        runYARA(pathToSample, yararules)
        runOLEID(pathToSample)
        runOLEDump(pathToSample)
        runViperMonkey(pathToSample)
    else:
        print(f"{Fore.CYAN}[*] INFO: {Style.RESET_ALL}Beginning analysis..")
        runDIE(pathToSample)
        runFloss(pathToSample)
        runB64Dump(pathToSample)
        runYARA(pathToSample, yararules)
        runCapa(pathToSample)
        runPEFrame(pathToSample)
        runSpeakeasy(pathToSample)
        runCobaltStrikeMetadata(pathToSample)

    print(f"{Fore.YELLOW}\n[----------------------------------------------------------------------------------------]")
    print(f"Analysis of {pathToSample} complete!".center(90))
    print(f"[----------------------------------------------------------------------------------------]\n{Style.RESET_ALL}")

if __name__ == "__main__":
    main()