#/user/bin/env python
#This script was built with the log format of the sshd that comes with ubuntu
#It assumes the year is the current year

import time
import datetime
from collections import defaultdict

def parse_time(line):
    split_line = line.split()

    time_bit = split_line[:3]
    time_string = ' '.join(split_line[:3] + [datetime.date.today().year])
    the_time = time.strptime(time_string, "%b %d %H:%M:%S:%Y")
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
    # Use -1 to prevent malicious attempts like `ssh "Invalid user"@here`
    info = line.split("Invalid user ")[-1]
    info = info.strip().split(" from ")
    info_dict = {"user":info[0], "ip":info[1], "port":None, "date":d}
    return info_dict

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

