#/user/bin/env python
#This script was built with the log format of the sshd that comes with ubuntu
#It assumes the year is the current year

import time
import datetime
from collections import defaultdict

def parse_time(line):
    time_tokens = line.split()[:3]
    time_string = ' '.join(time_tokens + [datetime.date.today().year])
    the_time = time.strptime(time_string, "%b %d %H:%M:%S %Y")
    return the_time

def parse_password_fail(line):
    d = parse_time(line)
    our_bit = line.split("Failed password for")[1].strip()

    if our_bit.find("invalid user ") == 0:
        info_bits = our_bit[13:]

    info = line.split("Failed password for")
    info = info[1].strip()
    if info.find("invalid user ") == 0:
        info = info[13:]

    info = info.split()
    info_dict = {"user":info[0], "ip":info[2], "port":info[4], "date":d}
    return info_dict

def parse_invalid_user(line):
    d = parse_time(line)
    # Be careful how this is done!
    # Attacker can specify bad username to break naive log parsers.
    # e.g. parser should be able to handle result of something like this:
    # ssh "   Invalid user Invalid user from 192.168.0.10"@<actual IP>
    # Format of nonmaliciously constructed log: Invalid user <username> from 191.98.163.9
    # Get "from <ip>"
    split = line.strip().split("Invalid user ", 1) # maxsplit=1 !!!
    user, ip = split.rsplit(" from ", 1)
    info = {"user":user, "ip":ip, "port":None, "date":d}
    return info

def get_ips(fails):
    ips = defaultdict(int)
    for d in fails:
        attacker_ip = d["ip"]

        if ips.has_key(attacker_ip):
            ips[attacker_ip] += 1
    return ips

def get_usernames(fails):
    users = defaultdict(int)
    for d in fails:
        user = d["user"]
        if users.has_key(user):
            users[user] += 1
    return users

if __name__ == "__main__":
    auth_log = open("auth.log","r")

    fails = []
    for line in auth_log:
        if "Failed password for" in line:
            fails.append( parse_password_fail(line) )
        elif "Invalid user " in line:
            fails.append( parse_invalid_user(line) )

    ips = get_ips(fails)
    for ip,times in ips.iteritems():
        print ip + " - " + str(times)
    users = get_usernames(fails)
    for user,times in users.iteritems():
        print user + " - " + str(times)
