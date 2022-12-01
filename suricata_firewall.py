#!/usr/bin/python3

import json
import subprocess
import datetime
import time
from sys import argv, exit

def main_loop(args):
    """Main loop that continually monitors Suricata eve.json"""

    #Create variables to store eve.json path and ipset list name
    
    path = args[1]
    blocklist = ip_list(args[2])
    current_time = datetime.datetime.utcnow()

    print("Checking current blocklist...")

    #Scan eve.json to find initial number of alerts

    print("Startup alert count...")

    initialAlertCount = alert_count_loop(log_formatter(path))
    currentAlertCount = initialAlertCount

    #Write to the log firewall start time and current number of alerts

    print(f"Current alerts in log {initialAlertCount} Time is {current_time}")

    with open ('/var/log/python_firewall.log', 'a') as f:
        f.write(f"---------------------------------------------------------------------------------\n")
        f.write(f"Firewall started at {current_time}\n")
        f.write(f"Current alerts in log {initialAlertCount}\n")

    #Parse eve.json on startup to add IPs to blocklist

    log_parser(log_formatter(path), blocklist)

    time.sleep(1)

    """Main loop. New alerts will be appended to a new list and scanned for relevant keywords.
       Alert counts updated per loop to determine if new alerts occurred since last check."""

    while True:
        try:
            currentAlertCount = alert_count_loop(log_formatter(path))
            if currentAlertCount > initialAlertCount:
                reducedLog = []
                updatedLog = log_formatter(path)
                for alert in updatedLog[(initialAlertCount - currentAlertCount):]:
                    reducedLog.append(alert)
                log_parser(reducedLog, blocklist)
                initialAlertCount = currentAlertCount
                time.sleep(5)
            else:
                time.sleep(5)
        except KeyboardInterrupt:
            print(f"Firewall stopped. Exiting. Time: {current_time}")
            with open('/var/log/python_firewall_error.log', 'a') as f:
                f.write('--------------------------------------------------------------------------------\n')
                f.write(f'Firewall manually stopped. Exited at {current_time} \n\n\n')
                exit()
        except Exception:
            print("Error occurred. Exiting. Time: {current_time}")
            with open('/var/log/python_firewall_error.log', 'a') as f:
                f.write('--------------------------------------------------------------------------------\n')
                f.write(f'Firewall error occurred. Exited at {current_time} \n')
                exit()


def log_parser(log, blocklist):
    """Scans eve.json for certain alerts based on keywords. If IP is already in ipset
    blocklist, the IP is not added"""

    src_keywords = ['DLL', 'EXE', 'SSH']
    dest_keywords = ['Dridex']

    ip = ''
    blocked_ips = blocklist

    current_time = datetime.datetime.utcnow()

    for i in log:
        if i['event_type'] == 'alert':
            for word in src_keywords:
                if word in i['alert']['signature']:
                    ip = i['src_ip']
                    if ip not in blocked_ips:
                        subprocess.run(f"ipset add blacklist {ip}", shell=True)
                        print(f"{ip} added at {current_time}")
                        blocked_ips.append(ip)
                        with open('/var/log/python_firewall.log', 'a') as f:
                            f.write('--------------------------------------------------------------------------------\n')
                            f.write(f"{ip} added at {current_time} Signature: {i['alert']['signature']}\n")  
                    else:
                        for word in dest_keywords:
                            if word in i['alert']['signature']:
                                ip = i['dest_ip']
                                if ip not in blocked_ips:
                                    subprocess.run(f"ipset add blacklist {ip}", shell=True)
                                    print(f"{ip} added at {current_time}")
                                    blocked_ips.append(ip)
                                    with open('/var/log/python_firewall.log', 'a') as f:
                                        f.write('--------------------------------------------------------------------------------\n')
                                        f.write(f"{ip} added at {current_time} Signature: {i['alert']['signature']}\n")  

    

def alert_count_loop(alerts_list):
    """Gets current amount of alerts in eve.json"""
    
    formatted_alerts = alerts_list
    alert_count = 0
    

    for i in formatted_alerts:
        if i['event_type'] == 'alert':
            alert_count += 1

    return alert_count


def log_formatter(log):
    """Formats eve.json into a list of python dictionaries"""

    formatted_alerts = []

    with open(log, 'r') as f:
        data = f.readlines()

    for alert in data:
        formatted_alerts.append(json.loads(alert))

    return formatted_alerts


def ip_list(ipset_list):
    """Gather IPs in ipset blocklist"""

    output = subprocess.run(f"ipset list {ipset_list}", shell=True, capture_output=True, text=True)
    output = output.stdout.split('\n')

    ips = [i for i in output[8:-1]]

    return ips


main_loop(argv)
