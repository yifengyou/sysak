# -*- coding: utf-8 -*-

"""
This script tries to collect system info, like OS/kernel veresion,
CPU/MEM/Block/NIC spec, hotfix info etc.

"""

import os
import sys
import time
import subprocess
import re
import json

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

def query(sn, data):
    result = {"success":"true","errorCode":"200","errorMsg":"",
        "fields":{}}
    try:
        cmd = 'khotfix-view -r 2>/dev/null'
        output = os.popen(cmd)
        result['fields']['hotfix'] = output.read()
        output.close()

        cmd = 'cat /proc/version 2>/dev/null'
        output = os.popen(cmd)
        result['fields']['kernel_version'] = output.read()
        output.close()

        result['fields']['cpuinfo'] = {}
        cmd = 'cat /proc/cpuinfo 2>/dev/null'
        output = os.popen(cmd)
        cpuinfo = output.read()
        if len(cpuinfo) > 0:
            cpuinfo = cpuinfo.splitlines()
            cpuinfo = cpuinfo[::-1]
            for line in cpuinfo:
                if line.startswith('processor'):
                    result['fields']['cpuinfo']['cpunum'] = int(line.strip().split(':')[1].strip())+1
                    break
                elif line.startswith('flags'):
                    result['fields']['cpuinfo']['flags'] = line.strip().split(':')[1].strip()
                elif line.startswith('model name'):
                    result['fields']['cpuinfo']['model name'] = line.strip().split(':')[1].strip()
        output.close()

        result['fields']['meminfo'] = {}
        cmd = 'cat /proc/meminfo 2>/dev/null'
        output = os.popen(cmd)
        meminfo = output.read()
        if len(meminfo) > 0:
            meminfo = meminfo.splitlines()
            for line in meminfo:
                if line.startswith('MemTotal:'):
                    result['fields']['meminfo']['MemTotal'] = line.strip().split(':')[1].strip()
                elif line.startswith('MemFree:'):
                    result['fields']['meminfo']['MemFree'] = line.strip().split(':')[1].strip()
                elif line.startswith('MemAvailable:'):
                    result['fields']['meminfo']['MemAvailable'] = line.strip().split(':')[1].strip()
                elif line.startswith('Cached:'):
                    result['fields']['meminfo']['Cached'] = line.strip().split(':')[1].strip()
                elif line.startswith('Slab:'):
                    result['fields']['meminfo']['Slab'] = line.strip().split(':')[1].strip()
                elif line.startswith('SReclaimable:'):
                    result['fields']['meminfo']['SReclaimable'] = line.strip().split(':')[1].strip()
                elif line.startswith('Shmem:'):
                    result['fields']['meminfo']['Shmem'] = line.strip().split(':')[1].strip()
                elif line.startswith('AnonHugePages:'):
                    result['fields']['meminfo']['AnonHugePages'] = line.strip().split(':')[1].strip()
                elif line.startswith('AnonPages:'):
                    result['fields']['meminfo']['AnonPages'] = line.strip().split(':')[1].strip()
                elif line.startswith('Mlocked:'):
                    result['fields']['meminfo']['Mlocked'] = line.strip().split(':')[1].strip()
        output.close()

        result['fields']['blockinfo'] = {}
        cmd = 'df -h 2>/dev/null'
        output = os.popen(cmd)
        blockinfo = output.read()
        if len(blockinfo) > 0:
            blockinfo = blockinfo.splitlines()
            for line in blockinfo:
                if line.startswith('/dev/'):
                    line = line.strip().split()
                    result['fields']['blockinfo'][line[0]] = {}
                    result['fields']['blockinfo'][line[0]]['Size'] = line[1]
                    result['fields']['blockinfo'][line[0]]['Used'] = line[2]
        output.close()

        cmd = 'lspci -v | grep Ethernet 2>/dev/null'
        output = os.popen(cmd)
        result['fields']['nicinfo'] = output.read()
        output.close()
    except Exception as e:
        result = {"success":"false","errorCode":"-1","errorMsg":repr(e)}

    data = json.dumps(result)
    print( data)

def main():
    sn = ''
    data = {}
    query(sn, data)

if __name__ == "__main__":
    main()
