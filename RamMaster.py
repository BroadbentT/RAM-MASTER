#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#      PYTHON SCRIPT FILE FOR THE FORENSIC ANALYSIS OF WINDOWS MEMORY DUMP-FILES
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS AND CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic                                                               
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import json
import time
import os.path
import datetime
import pyfiglet
import linecache
import virustotal3.core

from termcolor import colored

colour1 = 'green'
colour2 = 'yellow'
colour3 = 'blue'
colour4 = 'red'

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Forensic                                                               
# Details : Conduct simple and routine tests on any user supplied arguements.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
   print("\nPlease run this python script as root...")
   exit(True)
else:
   API_KEY = "" # ENTER YOUR API KEY HERE
    
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Forensic
# Details : Create functional subroutine calls from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def dispBanner(variable):
   ascii_banner = pyfiglet.figlet_format(variable).upper()
   print(colored(ascii_banner.rstrip("\n"), colour4, attrs=['bold']))
   return   
   
def getTime():
   variable = str(datetime.datetime.now().time())
   variable = spacePadding(variable.split(".")[0], SP1)
   return variable
   
def spacePadding(variable, value):
   if len(variable) > value:
      variable = variable[:value]
   while len(variable) < value:
      variable += " "
   return variable

def prompt():
   print(colored("\n[!] Press ENTER to continue...", colour3), end = '')
   null = input("")
   return
   
def start():
   print(colored("[*] Analysing file, please wait...\n", colour3))
   return   
   
def virusParser(variable):
   os.system("touch temp.tmp")
   os.system("awk '/\"failure\":/'           " + variable + " > snip1.tmp 2>&1 temp.tmp")
   os.system("awk '/\"harmless\":/'	     " + variable + " > snip2.tmp 2>&1 temp.tmp")               
   os.system("awk '/\"malicious\":/'         " + variable + " > snip3.tmp 2>&1 temp.tmp")
   os.system("awk '/\"suspicious\":/'        " + variable + " > snip4.tmp 2>&1 temp.tmp")
   os.system("awk '/\"type-unsupported\":/'  " + variable + " > snip5.tmp 2>&1 temp.tmp")
   os.system("awk '/\"undetected\"/'         " + variable + " > snip6.tmp 2>&1 temp.tmp")
   os.system("awk '/\"meaningful_name\":/'   " + variable + " > snip7.tmp 2>&1 temp.tmp")
   os.system("rm " + variable)
   os.system("wc -l snip6.tmp > lines.tmp 2>&1 temp.tmp")
   return

def displayMenu():
   print('\u2554' + '\u2550'*14 + '\u2566' + '\u2550'*21 + '\u2566' + '\u2550'*33 + '\u2566' + '\u2550'*55 + '\u2566' + '\u2550'*(37) + '\u2557')
   print('\u2551' + " TIME " + colored(localTime[:5],colour1) + "   " + '\u2551' + " FILE", end=' ')
   if fileName[:7] == "UNKNOWN":
      print(colored(fileName[:SP0], colour2), end=' ')
   else:
      print(colored(fileName[:SP0], colour1), end=' ')
   print('\u2551' + " HIVE         OFFSET LOCATION    "  + '\u2551' + " USERNAME " + " "*11 + " NTFS PASSWORD HASH " + " "*14 + '\u2551' + "     VIRUSRTOTAL API INFORMATION     " + '\u2551') 
   print('\u2560' + '\u2550'*14 + '\u256C' + '\u2550'*21 + '\u256C' + '\u2550'*12 + '\u2566' + '\u2550'*20 + '\u256C' + '\u2550'*55 + '\u256C' + '\u2550'*(11) + '\u2566' + '\u2550'*(25) + '\u2563')
   
# ----------------------------------------------------------------------------------------------------------------------------------------------------
   
   print('\u2551' + " PROFILE      " + '\u2551', end=' ')
   if PR2 == "UNSELECTED         ":
      print(colored(PR2,colour2), end=' ')
   else:
      print(colored(PR2,colour1), end=' ')
   print('\u2551' + " SAM        " + '\u2551', end=' ')
   if SAM == "0x0000000000000000":
      print(colored(SAM,colour2), end=' ')
   else:
      print(colored(SAM,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(USR[0].upper(),colour1), end=' ')
   print(colored(PAS[0],colour1), end=' ')
   print('\u2551', end=' ')   
   print("API TOKEN " + '\u2551', end=' ')
   if token[:2] == "SU":
      print(colored(token,colour1), end=' ')
   else:
      print(colored(token,colour2), end=' ')
   print('\u2551')

# ----------------------------------------------------------------------------------------------------------------------------------------------------
   
   print('\u2551' + " HOST NAME    " + '\u2551', end=' ')
   if HST == "UNKNOWN            ":
      print(colored(HST[:20],colour2), end=' ')
   else:
      print(colored(HST[:20],colour1), end=' ')
   print('\u2551' + " SECURITY   " + '\u2551', end=' ')
   if SEC == "0x0000000000000000":
      print(colored(SEC,colour2), end=' ')
   else:
      print(colored(SEC,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(USR[1].upper(),colour1), end=' ')
   print(colored(PAS[1],colour1), end=' ')
   print('\u2551', end=' ')   
   print("LAST FILE " + '\u2551', end=' ')
   if testFile[:7] == "UNKNOWN":
      print(colored(testFile,colour2), end=' ')
   else:
      print(colored(testFile, colour1), end=' ')
   print('\u2551')
# ----------------------------------------------------------------------------------------------------------------------------------------------------
   
   print('\u2551' + " SERVICE PACK " + '\u2551', end=' ')
   if SVP == "0                  ":
      print(colored(SVP,colour2), end=' ')
   else:
      print(colored(SVP,colour1), end=' ')
   print('\u2551' + " COMPONENTS " + '\u2551', end=' ')
   if COM == "0x0000000000000000":
      print(colored(COM,colour2), end=' ')
   else:
      print(colored(COM,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(USR[2].upper(),colour1), end=' ')
   print(colored(PAS[2],colour1), end=' ')
   print('\u2551', end=' ')   
   print("FAILURE   " + '\u2551', end=' ')   
   if failure[:1] == "0":
      print(colored(failure,colour2), end=' ')
   else:
      print(colored(failure,colour1), end=' ')
   print('\u2551')

# ----------------------------------------------------------------------------------------------------------------------------------------------------
   
   print('\u2551' + " LOCAL TIME   " + '\u2551', end=' ')
   if DA2 == "NOT FOUND          ":
      print(colored(DA2,colour2), end=' ')
   else:
      print(colored(DA2,colour1), end=' ')
   print('\u2551' + " SOFTWARE   " + '\u2551', end=' ')
   if SOF == "0x0000000000000000":
      print(colored(SOF,colour2), end=' ')
   else:
      print(colored(SOF,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(USR[3].upper(),colour1), end=' ')
   print(colored(PAS[3],colour1), end=' ')
   print('\u2551', end=' ')   
   print("HARMLESS  " + '\u2551', end=' ')
   if harmless[:1] == "0":
      print(colored(harmless, colour2), end=' ')
   else:
      print(colored(harmless, colour1), end=' ')
   print('\u2551') 
   
# ----------------------------------------------------------------------------------------------------------------------------------------------------
   
   print('\u2551' + " LOCAL IP     " + '\u2551', end=' ')
   if HIP == "000.000.000.000    ":
      print(colored(HIP[:SP1],colour2), end=' ')
   else:
      print(colored(HIP[:SP1],colour1), end=' ')
   print('\u2551' + " SYSTEM     " + '\u2551', end=' ')
   if SYS == "0x0000000000000000":
      print(colored(SYS,colour2), end=' ')
   else:
      print(colored(SYS,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(USR[4].upper(),colour1), end=' ')
   print(colored(PAS[4],colour1), end=' ')
   print('\u2551', end=' ')   
   print("MALICIOUSR" + '\u2551', end=' ')
   if malicious[:1] == "0":
      print(colored(malicious, colour2), end=' ')
   else:
      print(colored(malicious, colour1), end=' ')
   print('\u2551')   

# ----------------------------------------------------------------------------------------------------------------------------------------------------
   
   print('\u2551' + " LOCAL PORT   " + '\u2551', end=' ')
   if POR[:1] == "0":
      print(colored(POR[:SP1],colour2), end=' ')
   else:
      print(colored(POR[:SP1],colour1), end=' ')
   print('\u2551' + " NTUSER     " + '\u2551', end=' ')
   if NTU == "0x0000000000000000":
      print(colored(NTU,colour2), end=' ')
   else:
      print(colored(NTU,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(USR[5].upper(),colour1), end=' ')
   print(colored(PAS[5],colour1), end=' ')
   print('\u2551', end=' ')   
   print("SUSPECT   " + '\u2551', end=' ')
   if suspicious[:1] == "0":
      print(colored(suspicious, colour2), end=' ')
   else:
      print(colored(suspicious, colour1), end=' ')
   print('\u2551')

# ----------------------------------------------------------------------------------------------------------------------------------------------------
   
   print('\u2551' + " PID VALUE    " + '\u2551', end=' ')
   if PI1[:2] == "0 ":
      print(colored(PI1[:SP1],colour2), end=' ')
   else:
      print(colored(PI1[:SP1],colour1), end=' ')
   print('\u2551' + " HARDWARE   " + '\u2551', end=' ')
   if HRD == "0x0000000000000000":
      print(colored(HRD,colour2), end=' ')
   else:
      print(colored(HRD,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(USR[6].upper(),colour1), end=' ')
   print(colored(PAS[6],colour1), end=' ')
   print('\u2551', end=' ')   
   print("UNSUPPORT " + '\u2551', end=' ')
   if unsupported[:1] == "0":
      print(colored(unsupported, colour2), end=' ')
   else:
      print(colored(unsupported, colour1), end=' ')
   print('\u2551') 

# ----------------------------------------------------------------------------------------------------------------------------------------------------
   
   print('\u2551' + " OFFSET VALUE " + '\u2551', end=' ')
   if OFF[:2] == "0 ":
      print(colored(OFF[:SP1],colour2), end=' ')
   else:
      print(colored(OFF[:SP1],colour1), end=' ')
   print('\u2551' + " DEFUALT    " + '\u2551', end=' ')
   if DEF == "0x0000000000000000":
      print(colored(DEF,colour2), end=' ')
   else:
      print(colored(DEF,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(USR[7].upper(),colour1), end=' ')
   print(colored(PAS[7],colour1), end=' ')
   print('\u2551', end=' ')
   print("UNDETECT  " + '\u2551', end=' ')
   if undetected[:1] == "0":
      print(colored(undetected, colour2), end=' ')
   else:
      print(colored(undetected, colour1), end=' ')
   print('\u2551')
# ----------------------------------------------------------------------------------------------------------------------------------------------------
   
   print('\u2551' + " PARAMETER    " + '\u2551', end=' ')
   if PRM == "UNSELECTED         ":
      print(colored(PRM[:SP1],colour2), end=' ')
   else:
      print(colored(PRM[:SP1],colour1), end=' ')
   print('\u2551' + " BOOT BCD   " + '\u2551', end=' ')
   if BCD == "0x0000000000000000":
      print(colored(BCD,colour2), end=' ')
   else:
      print(colored(BCD,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(USR[8].upper(),colour1), end=' ')
   print(colored(PAS[8],colour1), end=' ')
   print('\u2551', end=' ')   
   print("REAL NAME " + '\u2551', end=' ')
   if realname[:7] == "UNKNOWN":
      print(colored(realname, colour2), end=' ')
   else:
      print(colored(realname, colour1), end=' ')
   print('\u2551') 

# ----------------------------------------------------------------------------------------------------------------------------------------------------
   
   print('\u2551' + " DIRECTORY    " + '\u2551', end=' ')
   if DIR == "OUTCOME            ":
      print(colored(DIR[:SP1],colour2), end=' ')
   else:
      print(colored(DIR[:SP1],colour1), end=' ')
   print('\u2551' + " " + J[:9] + "  " + '\u2551', end=' ')
   if CUS == "0x0000000000000000":
      print(colored(CUS,colour2), end=' ')
   else:
      print(colored(CUS,colour1), end=' ')
   print('\u2551', end=' ')
   if USR[10] != "":
      print(colored(USR[9].upper(),colour4), end=' ')
      print(colored(PAS[9],colour4), end=' ')
   else:
      print(colored(USR[9].upper(),colour1), end=' ')
      print(colored(PAS[9],colour1), end=' ')
   print('\u2551', end=' ')   
   print("STATUSR   " + '\u2551', end=' ')
   if status[:7] == "UNKNOWN":
      print(colored(status, colour2), end=' ')
   else:
      if status[:8] == "HARMLESS":
         print(colored(status, colour1), end=' ')
      else:
         print(colored(status, colour4, attrs=['blink']), end=' ')
   print('\u2551') 
# ----------------------------------------------------------------------------------------------------------------------------------------------------

   print('\u2560' + ('\u2550')*14 + '\u2569'+ ('\u2550')*21  + '\u2569' + ('\u2550')*12 + '\u2569' + ('\u2550')*20 + '\u2569' + '\u2550'*55 + '\u2569' + ('\u2550')*11 +  '\u2569' + '\u2550'*(25) + '\u2563')

# ----------------------------------------------------------------------------------------------------------------------------------------------------

   print('\u2551', end=' ')
   print(" "*10, end=' ')
   print("GENERAL SETTINGS", end=' ')
   print(" "*18, end=' ')
   print("ANALYSE", end=' ')
   print(" "*17, end=' ')
   print("IDENTIFY", end=' ')
   print(" "*14, end=' ')
   print("INVESTIGATE", end=' ')
   print(" "*18, end=' ')
   print("EXTRACT", end=' ')
   print(" "*26, end=' ')
   print('\u2551')

# ----------------------------------------------------------------------------------------------------------------------------------------------------

   print('\u2560' + '\u2550'*164 + '\u2563')
   print('\u2551' + "(0) Re/Set PROFILE   (10) Re/Set SAM       (20) SAM       (30) List Registries (40) PrintKeys   (50) Desktop   (60) StationScan (70) RSA SSL Keys (80) Dump Eventlog" + '\u2551')
   print('\u2551' + "(1) Re/Set HOST NAME (11) Re/Set SECURITY  (21) SECURITY  (31) Users/Passwords (41) Shellbags   (51) Clipboard (61) SearchHooks (71) Hive  Cert's (81) Dump Timeline" + '\u2551')
   print('\u2551' + "(2) Re/Set SERV PACK (12) Re/Set COMPONENT (22) COMPONENT (32) Running Process (42) ShimCaches  (52) Notepad   (62) DesktopScan (72) Kern Drivers (82) Dump  Screens" + '\u2551')
   print('\u2551' + "(3) Re/Set TIMESTAMP (13) Re/Set SOFTWARE  (23) SOFTWARE  (33) Hidden  Process (43) ConnectScan (53) Explorer  (63) JobLinkInfo (73) DllDump  PID (83) Dump  MFTable" + '\u2551')
   print('\u2551' + "(4) Re/Set LOCAL IP  (14) Re/Set SYSTEM    (24) SYSTEM    (34) Proc Privileges (44) NetworkScan (54) ListFiles (64) MBR  Parser (74) MalFind  PID (84) PCAP  Extract" + '\u2551')
   print('\u2551' + "(5) Re/Set LOCALPORT (15) Re/Set NTUSER    (25) NTUSER    (35) Running Service (45) Socket Scan (55) SymLinks  (65) Object Scan (75) VadDump  PID (85) Bulk  Extract" + '\u2551')
   print('\u2551' + "(6) Re/Set PID VALUE (16) Re/Set HARDWARE  (26) HARDWARE  (36) Service   SID's (46) Mutant Scan (56) Drivers   (66) All Modules (76) ProcDump PID (86) Load  MemFile" + '\u2551')
   print('\u2551' + "(7) Re/Set OFFSET    (17) Re/Set DEFUALT   (27) DEFUALT   (37) Un/Linked Dll's (47) Assist Keys (57) List SIDs (67) BioKeyboard (77) Mem-Dump PID (87) Shell MemFile" + '\u2551')
   print('\u2551' + "(8) Re/Set PARAMETER (18) Re/Set BOOT BCD  (28) BOOT BCD  (38) Command History (48) SessionData (58) EnvVars   (68) CmdlineArgs (78) PARAM Search (88) Virus Checker" + '\u2551')
   print('\u2551' + "(9) Re/Set DIRECTORY (19) Re/Set "+J[:9]+" (29) "+J[:9]+" (39) Console History (49) DomainHashs (59) TrueCrypt (69) Yara Search (79) PARAM OFFSET (89) Exit  Program" + '\u2551')
   print('\u255A' + '\u2550'*164 + '\u255D')
   return
   
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Forensic
# Details : Boot the system and populate system variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

os.system("clear")
os.system("xdotool key Alt+Shift+S; xdotool type 'RAM MASTER'; xdotool key Return")
dispBanner("RAM  MASTER")
print(colored("BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS\n", 'yellow', attrs=['bold']))
print("Booting - Please wait...")

if not os.path.exists('OUTCOME'):
   os.mkdir("OUTCOME")     

if not os.path.exists("volatility_2.6_lin64_standalone"):
   print("Downloading volatility 2.6 for linux...\n")
   os.system("wget https://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip")
   os.system("unzip volatility_2.6_lin64_standalone.zip")
   os.remove("volatility_2.6_lin64_standalone.zip")
else:
   time.sleep(5)

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Forensic
# Details : Initialise program variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

SP0 = 14
SP1 = 19
SP2 = 18
SP3 = 20
SP4 = 32
SP5 = 23
MAX = 11
LDF = 0

PRO = spacePadding("UNSELECTED",SP1)
PR2 = spacePadding("UNSELECTED",SP1)
HST = spacePadding("UNKNOWN",SP1)
SVP = spacePadding("0",SP1)
DA1 = spacePadding("NOT FOUND",SP1)
DA2 = spacePadding("NOT FOUND",SP1)
HIP = spacePadding("000.000.000.000",SP1)
POR = spacePadding("0",SP1)
PI1 = spacePadding("0",SP1)
PI2 = spacePadding("0",SP1)
OFF = spacePadding("0",SP1)
PRC = spacePadding("0",SP1)
PRM = spacePadding("UNSELECTED",SP1)
DIR = spacePadding("OUTCOME",SP1)

SAM = "0x0000000000000000"
SEC = "0x0000000000000000"
COM = "0x0000000000000000"
SOF = "0x0000000000000000"
SYS = "0x0000000000000000"
NTU = "0x0000000000000000"
HRD = "0x0000000000000000"
DEF = "0x0000000000000000"
BCD = "0x0000000000000000"
CUS = "0x0000000000000000"
J   = spacePadding("CUSTOM",SP2)

XX1 = " "*SP3
XX2 = " "*SP4
USR= [XX1]*MAX
PAS= [XX2]*MAX

fileName    = spacePadding("UNKNOWN",SP5)   
testFile    = spacePadding("UNKNOWN",SP5)
failure     = spacePadding("0", SP5)
harmless    = spacePadding("0", SP5)
malicious   = spacePadding("0", SP5)
suspicious  = spacePadding("0", SP5)
unsupported = spacePadding("0", SP5)
undetected  = spacePadding("0", SP5)
realname    = spacePadding("UNKNOWN", SP5)
status      = spacePadding("UNKNOWN", SP5)

if API_KEY != "":
   token = spacePadding("SUBSCRIBED",SP5)
else:
   token = spacePadding("UNSUBSCRIBED",SP5)
   
volpath  = "volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone"

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Forensic
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   os.system("rm *.tmp")
   localTime = getTime()
   linecache.clearcache()
   os.system("clear")
   displayMenu()
   print(colored("[?] Please select a task: ", colour3), end = '')
   selection = input("")
   if selection == "89":
      LDF = 1
   if selection != "86" and LDF == 0:
      print(colored("[-] You need to select a file first, before you can analyse it...", colour4))
      selection = "86"

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Lets the user select a new Windows profile.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='0':
      BAK = PRO
      MATCH = 0
      print(colored("[?] Please enter profile: ", colour3), end = '')
      PRO = input("")
      if PRO == "":
         PRO = BAK      
      with open("profiles.txt") as search:
         line = search.readline()
         while line:
            line = search.readline()
            if PRO in line:
               MATCH = 1  
      if MATCH == 0:
         PRO = BAK
         print(colored("[-] The profile you entered was not valid, check 'profiles.txt' for a valid profile...", colour4))
      else:
         PRO = " --profile " + PRO
         PR2 = PRO.replace(" --profile ","") 
         PR2 = spacePadding(PR2, SP1)
      prompt()
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to change the HOST name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '1':
      print(colored("[?] Please enter HOST name: ", colour3), end = '')
      value = input("")
      if value != '':
         HST = spacePadding(value, SP1)
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to change the SERVICE PACK version. 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '2':
      print(colored("[?] Please enter SERVICE PACK name: ", colour3), end = '')
      value = input("")
      if value != '':
         SVP = spacePadding(value, SP1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to change the localTime STAMP. 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '3':
      print(colored("[?] Please enter TIMESTAMP: ", colour3), end = '')
      value = input("")
      if value != '':
         DA2 = spacePadding(value, SP1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to set the host IP value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '4':
      print(colored("[?] Please enter IP value: ", colour3), end = '')
      value = input("")
      if value != '':
         HIP = spacePadding(value, SP1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to Set host PORT value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '5':
      print(colored("[?] Please enter PORT value: ", colour3), end = '')
      value = input("")
      if value != '':
         POR = spacePadding(value, SP1)
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to set the PID value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '6':
      print(colored("[?] Please enter PID value: ", colour3), end = '')
      value = input("")
      if value != '':
         PI1 = spacePadding(value, SP1)
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to set the OFFSET value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '7':
      print(colored("[?] Please enter OFFSET value: ", colour3), end = '')
      value = input("")
      if value != '':
         OFF = spacePadding(value, SP1)
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to set the PARAMETER string.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '8':
      print(colored("[?] Please enter parameter value: ", colour3), end = '')
      value = input("")
      if value != '':
         PRM = spacePadding(value,SP1)
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to change the working directory.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '9':
      print(colored("[?] Please enter new working directory value: ", colour3), end = '')
      directory = input("")
      if os.path.exists(directory):
         print(colored("[-] Sorry, this directory already exists....", colour4))
      else:
         if len(directory) > 0:
            os.mkdir(directory)
            DIR = directory
            DIR = spacePadding(DIR, SP1)
            print(colored("[+] Working directory changed...", colour3))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change SAM via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '10':
      print(colored("[?] Please enter SAM value: ", colour3), end = '')
      value = input("")
      if value != "":
         SAM = spacePadding(value, SP2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change SECURITY via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '11':
      print(colored("[?] Please enter SECURITY value: ", colour3), end = '')
      value = input("")
      if value != "":
         SEC = spacePadding(value, SP2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change COMPENENTS via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '12':
      print(colored("[?] Please enter COMPONENTS value: ", colour3), end = '')
      value = input("")
      if value != "":
         COM = spacePadding(value, SP2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change SOFTWARE via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '13':
      print(colored("[?] Please enter SOFTWARE value: ", colour3), end = '')
      value = input("")
      if value != "":
         SOF = spacePadding(value, SP2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change SYSTEM via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '14':
      print(colored("[?] Please enter SYSTEM value: ", colour3), end = '')
      value = input("")
      if value != "":
         SYS = spacePadding(value, SP2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change NTUSER via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '15':
      print(colored("[?] Please enter NTUSER value: ", colour3), end = '')
      value = input("")
      if value != "":
         NTU = spacePadding(value, SP2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change HARDWARE via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '16':
      print(colored("[?] Please enter HARDWARE value: ", colour3), end = '')
      value = input("")
      if value != "":
         HRD = spacePadding(value, SP2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change DEFAULT via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '17':
      print(colored("[?] Please enter DEFUALT value: ", colour3), end = '')
      value = input("")
      if value != "":
         DEF = spacePadding(value, SP2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change BOOT BCD via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '18':
      print(colored("[?] Please enter BOOT BCD value: ", colour3), end = '')
      value = input("")
      if value != "":
         BCD = spacePadding(value, SP2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change CUSTOM via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '19':
      print(colored("[?] Please enter " + J.rstrip(" ") + " name: ", colour3), end = '')
      value = input("")
      if value != "":
         J = spacePadding(value, 9)         
      print(colored("[?] Please enter " + J.rstrip(" ") + " value: ", colour3), end = '')
      value = input("")   
      if value != "":
         CUS = spacePadding(value, SP2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows SAM hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '20':
      if (SAM == "0x0000000000000000"):
         print(colored("[-] SAM Hive missing - it is not possible to extract data...", colour4))
      else:
         start()
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " hivedump -o " + SAM + " | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows SECURITY hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='21':
      if (SEC == "0x0000000000000000"):
         print(colored("[-] SECURITY Hive missing - it is not possible to extract data...", colour4))
      else:
         start()
         os.system(volpath + " -f " + fileName.rstrip(" ") + PRO + " hivedump -o " + SEC + " | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows COMPONENTS hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='22':
      if (COM == "0x0000000000000000"):
         print(colored("[-] COMPONENTS Hive missing - it is not possible to extract data...", colour4))
      else:
         start()
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " hivedump -o " + COM + " | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows SOFTWARE hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='23':
      if (SOF == "0x0000000000000000"):
         print(colored("[-] SOFTWARE Hive missing - it is not possible to extract data...", colour4))
      else:
         start()
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " hivedump -o " + SOF + " | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows SYSTEM hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='SP5':
      if (SYS == "0x0000000000000000"):
         print(colored("[-] SYSTEM Hive missing - it is not possible to extract data...", colour4))
      else:
         start()
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " hivedump -o " + SYS + " | more")
      prompt()    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows NTUSER hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='25':
      if (NTU == "0x0000000000000000"):
         print(colored("[-] NTUSER (Administrator) Hive missing - it is not possible to extract data...",colour4))
      else:
         start()
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " hivedump -o " + NTU + " | more")
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows HARDWARE hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='26':
      if (HRD == "0x0000000000000000"):
         print(colored("[-] HARDWARE Hive missing - it is not possible to extract data...",colour4))
      else:
         start()
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " hivedump -o " + HRD + " | more")
      prompt()     

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows DEFUALT hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='27':
      if (DEF == "0x0000000000000000"):
         print(colored("[-] DEFUALT Hive missing - it is not possible to extract data...", colour4))
      else:
         start()
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " hivedump -o " + DEF + " | more")
      prompt()   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows BOOT BCD hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='28':
      if (BCD == "0x0000000000000000"):
         print(colored("[-] BOOT BCD Hive missing - it is not possible to extract data...",colour4))
      else:
         start()
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " hivedump -o " + BCD + " | more")
      prompt()   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows CUSTOM hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='29':
      if (CUS == "0x0000000000000000"):
         print(colored("[-] " + J.rstrip(" ") + " Hive missing - it is not possible to extract data...",colour4))
      else:
         start()
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " hivedump -o " + CUS + " | more")
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Display all hives.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '30':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " hivelist | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Dumps the SAM file hashes for export to hashcat and display any LSA secrets.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '31':
      start()
      if SAM == "0x0000000000000000":
         print(colored("[-] SAM HIVE missing - its not possible to extract the hashes...",colour4))
      else:
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " hashdump -y " + SYS + " -s " + SAM + " | more")         
      print("")
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " lsadump | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows running processes and provides a brief analyse.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '32':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " psscan | more | tee -a F1.tmp")
      os.system("sed -i '/^$/d' F1.tmp")
      os.system("sed -i '1d' F1.tmp")
      os.system("sed -i '1d' F1.tmp")
      with open("F1.tmp","r") as read1, open("pid.tmp","w") as write1, open("ppid.tmp","w") as write2:
         for line in read1:
            line = " ".join(line.split())
            null1,null2,pid,ppid,*null3 = line.split(" ")
            write1.write(pid+"\n")
            write2.write(ppid+"\n")            
      os.system("cat F1.tmp | wc -l > count.tmp")
      count = (linecache.getline("count.tmp", 1).rstrip("\n"))     
      print(colored("\n[+] There were " + str(count) + " processes running at the time of the memory dump.", colour3))            
      os.system("echo 'comm -13 <(sort -u pid.tmp) <(sort -u ppid.tmp) > suspect.tmp' > patch.sh")
      os.system("bash patch.sh")
      os.system("sort -n suspect.tmp > suspect2.tmp")
      print(colored("[+] Analyse of these processes reveals that:", colour3))
      with open('suspect2.tmp') as read5:
         for line in read5:
            line  = line.rstrip('\n')
            if (line != "") and (line != "0") and ("x" not in line):
               print(colored("\tParent process PPID " + str(line) + " does not have a process spawn! and should be investigated further...", colour3))
      os.remove("patch.sh")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows hidden processes.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '33':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " psxview | more")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows processes pivs.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '34':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " privs | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows running services.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '35':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " svcscan | more")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Names of services in the Registry/Calculated SID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='36':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " getservicesids | more")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - List running dll's/Detect unlinked dll's.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='37':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " ldrmodules | more")
      print(" ")
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " dlllist | more")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Last commands run.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '38':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " cmdscan | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Last commands run.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '39':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " consoles | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Print specified key from hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='40':
      print(colored("[?] Please enter key value in quotes: ", colour3), end = '')
      KEY = input("")
      if KEY != "":
         start()
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " printkey -K " + KEY + " | more")
         prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shellbags.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='41':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " shellbags | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shellbags.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='42':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " shimcache | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Analyse the NETWORK connections.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='43':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " connscan | more")
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Analyse the NETWORK traffic.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='44':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " netscan | more")
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Analyse the NETWORK sockets.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='45':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " sockets | more")
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Finds Mutants.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='46':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " mutantscan | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Show userassist key values.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '47':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " userassist | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows sessions history.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='48':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " sessions | more")
      prompt()     
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Dump domain hashes.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='49':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " cachedump | more")
      prompt()    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows desktop information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='50':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " deskscan | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows clipboard information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='51':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " clipboard | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows notepad information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='52':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " notepad | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows IE history.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='53':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " iehistory | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows files.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='54':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " filescan | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows symlinks.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='55':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " symlinkscan | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows drivers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='56':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " devicetree | more")
      print("")
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " driverscan | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Display all SID's.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='57':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " getsids | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Display environmental variables.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='58':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " envars | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - TrueCrypt info
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='59':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " truecryptsummary | more")
      print("")
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " truecryptmaster | more")
      print("")
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " truecryptpassphrase | more")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Pool scanner for window stations
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='60':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " wndscan | more")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Detect hooks
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='61':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " apihooks | more")
      print("")
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " eventhooks | more")
      print("")
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " messagehooks | more")
      prompt()      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Poolscaner for tagDESKTOP (desktops)
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='62':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " deskscan | more")
      prompt()   
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected -  Print process job link information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='63':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " joblinks | more")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Scans for and parses potential Master Boot Records.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='64':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " mbrvirusParser | more")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Scan for Windows object type objects.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='65':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " objtypescan | more")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Print list of loaded modules/unloaded modules.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='66':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " modules | more")
      print("")
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " unloadedmodules | more")            
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Reads the keyboard buffer from Real Mode memory.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='67':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " bioskbd | more")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Last commands run.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '68':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " cmdline | more")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Yara scan.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='69':
      print(colored("[?] Please enter yara string to scan: ", colour3), end = '')
      scanString = input("")
      if scanString != "":
         start()
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " yarascan -Y " + scanString + " | more")
         prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Dump private and public RSA SSL keys.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='70':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " dumpcerts -D " + DIR)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Dump registry Hives.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='71':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " dumpregistry -D " + DIR)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Dump kernal drivers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='72':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " moddump -D " + DIR)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - List running dll's for process PID and dump.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='73':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " dlldump -p " + PI1 + " -D " + DIR)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Finds Malware.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='74':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " malfind -p " + PI1 + " -D " + DIR)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected -  Vad dump PID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='75':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " vaddump -p " + PI1 + " --dump-dir " + DIR)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Proc dump PID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='76':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " procdump  -p " + PI1 + " --dump-dir " + DIR)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Memory dump PID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='77':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " memdump  -p " + PI1 + " --dump-dir " + DIR)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Search image for occurences of string.
# Modified: N/A
# ------------------------------------------------------------------------------------- 
   
   if selection =='78':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " pslist | grep " + PRM + " | more")
      print("")
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " filescan | grep " + PRM + " | more")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Extract a single file based on physical OFFSET.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='79':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " dumpfiles -Q " + OFF + " -D " + DIR + " -u -n")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected -
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '80':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " evtlogs -D " + DIR)
      print("")
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " --save-evt evtlogs -D " + DIR)      
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Extract timeline.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='81':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " timeliner --output-file='" + DIR.rstrip(" ") + "/timeline.txt'")
      print("")
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " shellbags --output-file='" + DIR.rstrip(" ") + "/time.txt'")
      prompt()

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Extract windows screenshots.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='82':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " -D " + DIR + " screenshot")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Extract the MFT table and it contents.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='83':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " mftvirusParser --output-file=" + DIR.rstrip(" ") + "/mfttable.txt")     
      print("")
      os.system("strings " + DIR.rstrip(" ") + "/mfttable.txt | grep '0000000000:' > count.tmp")
      fileNum = sum(1 for line in open('count.tmp'))
      print(colored("[+] The table contains " + str(fileNum) + " local files < 1024 bytes in length.", colour3))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Bulk Extract all known files.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='84':
      start()
      os.system("bulk_extractor -x all -e net -o " + DIR + " '" + fileName.rstrip(" ") + "'")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Bulk Extract all known files.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='85':
      start()
      os.system("bulk_extractor -o " + DIR + " '" + fileName.rstrip(" ") + "'")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Select file & extract host variables.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '86':
      bak = fileName
      print(colored("[?] Please enter filename: ", colour3), end = '')
      fileName = input("")
      if fileName == "":
         fileName = bak
      if os.path.exists(fileName.rstrip(" ")):
         profiles = "NOT FOUND"
         LDF = 1
         start()
         os.system(volpath + " imageinfo -f '" + fileName.rstrip(" ") + "' --output-file=image.log")
         with open("image.log") as search:
            for line in search:
               if "Suggested Profile(s) :" in line:
                  profiles = line
               if "Number of Processors" in line:
                  PRC = line
               if "Image Type (Service Pack) :" in line:
                  SVP = line
               if "Image date and time :" in line:
                  DA1 = line
               if "Image local date and time :" in line:
                  DA2 = line                  
         if profiles == "NOT FOUND":
            print(colored("[#] ERROR #001 - A windows profile was not found, see 'image.log' for further information.", colour4))
            exit(True)                     
         profiles = profiles.replace("Suggested Profile(s) :","")
         profiles = profiles.replace(" ","")
         profiles = profiles.split(",")
         PRO = " --profile " + profiles[0]
         PR2 = profiles[0]         
         if (PR2[:1] != "W") and (PR2[:1] != "V"):
            print(colored("[#] ERROR #002 - A windows profile was not found, see 'image.log' for further information.", colour4))
            exit(True)
         else:
            PR2 = spacePadding(PR2,SP1)
            os.remove("image.log")               
         PRC = PRC.replace("Number of Processors :","")
         PRC = PRC.replace(" ","")
         PRC = PRC.replace("\n","")
         PRC = spacePadding(PRC, SP3)
         SVP = SVP.replace("Image Type (Service Pack) :","")
         SVP = SVP.replace(" ","")
         SVP = SVP.replace("\n","")
         SVP = spacePadding(SVP, SP1)
         DA1 = DA1.replace("Image date and time :","")
         DA1 = DA1.lstrip() 
         DA1 = DA1.rstrip("\n")
         a,b,c = DA1.split()
         DA1 = a + " @ " + b
         DA2 = DA2.replace("Image local date and time :","")
         DA2 = DA2.lstrip()
         DA2 = DA2.rstrip("\n")
         a,b,c = DA2.split()
         DA2 = a + " " + b
         DA2 = spacePadding(DA2, SP1)                  
         print("")
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " hivelist --output-file=hivelist.tmp")
         if os.path.exists("hivelist.tmp"):
            with open("hivelist.tmp") as search:
               for line in search:
                 if "\sam" in line.lower():
                    SAM = line.split(None, 1)[0]
                    SAM = spacePadding(SAM, SP2)
                 if "\security" in line.lower():
                    SEC = line.split(None, 1)[0]
                    SEC = spacePadding(SEC, SP2)
                 if "\software" in line.lower():
                    SOF = line.split(None, 1)[0]
                    SOF = spacePadding(SOF, SP2)
                 if "\system" in line.lower():
                    SYS = line.split(None, 1)[0]
                    SYS = spacePadding(SYS, SP2)
                 if "\components" in line.lower():
                    COM = line.split(None, 1)[0]
                    COM = spacePadding(SYS, SP2)
                 if "\\administrator\\ntuser.dat" in line.lower(): # \Administrator\NTUSER.DAT as there are usually multiple NTUSERS files. 
                    NTU = line.split(None, 1)[0]
                    NTU = spacePadding(SYS, SP2)
                 if "\hardware" in line.lower():
                    HRD = line.split(None,1)[0]
                    HRD = spacePadding(HRD, SP2)
                 if "\default" in line.lower():
                    DEF = line.split(None,1)[0]
                    DEF = spacePadding(DEF, SP2)
                 if "\\bcd" in line.lower():
                    BCD = line.split(None,1)[0]
                    BCD = spacePadding(BCD, SP2)                                  
         print("")
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " printkey -o " + SYS + " -K 'ControlSet001\Control\ComputerName\ComputerName' --output-file=host.tmp")
         if os.path.exists("host.tmp"):
            with open("host.tmp") as search:
               wordlist = (list(search)[-1])
               wordlist = wordlist.split()
               HST = str(wordlist[-1])
            if HST == "searched":					# Looks like a host name has not been found.
               HST = "NOT FOUND          "				# So set a defualt value.
            else:
               HST = HST.encode(encoding='UTF-8',errors='strict')	# Deal with a encoding issue within hostname.
               HST = str(HST)
               HST = HST.replace("b'","")
               HST = HST.replace("\\x00'","")
               HST = spacePadding(HST, SP1)         
         print("")
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " hashdump -y " + SYS + " -s " + SAM + " --output-file=hash.tmp")
         if os.path.exists("hash.tmp"):
            with open("hash.tmp") as search:
               count = 0
               for line in search:
                  if line != "":
                     catch = line.replace(":"," ")
                     catch2 = catch.split()
                     catch3 = catch2[3]
                     PAS[count] = catch3
                     USR[count] = catch2[0][:SP3-1] + " "
                     USR[count] = spacePadding(USR[count], SP3)
                  count = count + 1
               if count > MAX: count = MAX                
         print("")
         os.system(volpath + " -f '" + fileName.rstrip(" ") + "'" + PRO + " connscan --output-file=connscan.tmp")
         if os.path.exists("connscan.tmp"):
            os.system("sed -i '1d' connscan.tmp")
            os.system("sed -i '1d' connscan.tmp")
            os.system("cut -f 2 -d ' ' connscan.tmp > conn1.tmp")
            os.system("strings conn1.tmp | sort | uniq -c | sort -nr > connscan.tmp")
            os.system("sed -i /'127'/d connscan.tmp")
            getip = linecache.getline('connscan.tmp', 1)
            if getip != "":
               getip = getip.replace("      ","")
               null,getip = getip.split(" ")
               getip = getip.replace(':',' ')
               HIP = getip.rsplit(' ', 1)[0]
               POR = getip.rsplit(' ', 1)[1]
               HIP = spacePadding(HIP.rstrip("\n"), SP1)
               POR = spacePadding(POR.rstrip("\n"), SP1)
      else:
         print(colored("[-] I am Sorry, I cannot find " + fileName.rstrip(" ") + "- did you spell it correctly?....", colour4))
      if len(fileName) < SP5:
         fileName = spacePadding(fileName, SP5)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shell in.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '87':
      start()
      os.system(volpath + " -f '" + fileName.rstrip(" ") + "' " + PRO + " volshell") 
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Virus Total via API
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '88':
      if API_KEY != "":
         print(colored("[*] Checking status of file via virustotal.com api...\n", colour3))
         os.chdir(DIR)
         os.system("ls -la")
         print(colored("\n[?] Please enter filename to analyse: ", colour3), end = '')
         testFile = input("")
         if testFile != "":
            if os.path.exists(testFile):
               os.system("md5sum " + testFile + " > analyse.tmp")
               hash = linecache.getline('analyse.tmp', 1)
               hash = hash.split(" ")[0]
               vt = virustotal3.core.Files(API_KEY)      
               vt_files = virustotal3.core.Files(API_KEY)      
               result = vt_files.info_file(hash)
               print(json.dumps(result, indent=5, sort_keys=True))               
               with open("analyse.tmp", "w") as parse:
                  parse.write(json.dumps(result, indent=5, sort_keys=True))               
               virusParser("analyse.tmp")               
               failure     = linecache.getline('snip1.tmp', 1)
               harmless    = linecache.getline('snip2.tmp', 1)
               malicious   = linecache.getline('snip3.tmp', 1)
               suspicious  = linecache.getline('snip4.tmp', 1)
               unsupported = linecache.getline('snip5.tmp', 1)
               undetected  = linecache.getline('lines.tmp', 1)
               realname    = linecache.getline('snip7.tmp', 1)    
               failure     = failure.split(":")[1].replace(",","")
               harmless    = harmless.split(":")[1].replace(",","")
               malicious   = malicious.split(":")[1].replace(",","")
               suspicious  = suspicious.split(":")[1].replace(",","")
               unsupported = unsupported.split(":")[1].replace(",","")
               undetected  = undetected.replace("snip6.tmp","")
               realname    = realname.split(":")[1].replace(",","")    
               failure     = failure.strip(" ")
               harmless    = harmless.strip(" ")
               malicious   = malicious.strip(" ")
               suspicious  = suspicious.strip(" ")
               unsupported = unsupported.strip(" ")
               undetected  = undetected.strip(" ")
               realname    = realname.replace('"','')
               realname    = realname.strip(" ")               
               failure     = failure.rstrip("\n")
               harmless    = harmless.rstrip("\n")
               malicious   = malicious.rstrip("\n")
               suspicious  = suspicious.rstrip("\n")
               unsupported = unsupported.rstrip("\n")
               undetected  = undetected.rstrip("\n")
               undetected  = int(undetected)
               undetected  = str(undetected -1)
               realname    = realname.rstrip("\n")
               realname    = realname.rstrip("\n")        
               testFile    = spacePadding(testFile, SP5)
               failure     = spacePadding(failure, SP5)
               harmless    = spacePadding(harmless,SP5)
               malicious   = spacePadding(malicious,SP5)
               suspicious  = spacePadding(suspicious,SP5)
               unsupported = spacePadding(unsupported,SP5)
               undetected  = spacePadding(undetected,SP5)
               realname    = spacePadding(realname,SP5)   
               if malicious[:1] == "0":
                  status = spacePadding("HARMLESS",SP5)
               else:
                  status = spacePadding("MALICIOUS", SP5)                
               os.system("rm *.tmp")
            else:
               print(colored("[-] I am sorry, I could not find " + testFile.rstrip(" ") + " - did you spell it correctly?...", colour4))
         os.chdir("..")
      else:
         print(colored("[-] I am Sorry, you need to enter your personal api key on line 46 of this script...", colour4))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Exit the program.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='89':
      exit(1)
#Eof...


