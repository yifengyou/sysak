# -*- coding: utf-8 -*-
# @Author: tuquan

import os
import sys
import time
import subprocess
import re

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
import collect_data
import crash
import utils

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

# Return whether need long time to finish
def need_long_time():
    return True

def getReasmFails(sn,data):
    cmd = "cat /proc/net/snmp | grep \"^Ip\" | tail -n 1 | awk '{print $(NF-3)}'"
    ret = collect_data.get_cmddata(sn,data,cmd,1).strip()
    return ret

def doPingRoute(sn,data):
    cmd = "ping -c 1 -s 9000 `ip route | grep via | head -n 1 | awk '{print $3}'`"
    ret = collect_data.get_cmddata(sn,data,cmd).strip()
    #print "print ret : ",ret
    return ret

def query(sn, data):
    ret = utils.get_script_result(sn,data)
    if ret:
        return ret

    ret = {}
    ret['return'] = True
    ret['solution'] = utils.format_result(desc=("ping大包丢包"),
        solution=("Try to increase /proc/sys/net/ipv4/ipfrag_high_thresh twice"))

    cmd1 = 'cat /proc/cpuinfo | grep "processor" | wc -l'
    cpu_num = collect_data.get_cmddata(sn,data,cmd1).strip()

    cmd2 = 'cat /proc/sys/net/ipv4/ipfrag_high_thresh'
    high_thresh = collect_data.get_cmddata(sn,data,cmd1).strip()

    if cpu_num*130000 < high_thresh :
        ret['return'] = False
        ret['solution'] = 'Not match'
        utils.cache_script_result(sn,data,ret)
        print( __name__,':',ret)
        return ret

    ReasmFails1 = getReasmFails(sn,data)
    doPingRoute(sn,data)
    time.sleep(3)
    ReasmFails2 = getReasmFails(sn,data)
    if ReasmFails2 == ReasmFails1:
        ret['return'] = False
        ret['solution'] = 'Not match'

    utils.cache_script_result(sn,data,ret)
    print( __name__,':',ret)
    return ret

def main():
    sn = ''
    data = {}
    query(sn, data)

if __name__ == "__main__":
    main()
