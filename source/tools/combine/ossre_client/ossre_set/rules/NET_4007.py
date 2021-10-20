# -*- coding: utf-8 -*-
# @Author: shiyan

"""
We define a unique ID for every rule,
SCHED rules use 1000-1999
MEM rules use 2000-2999
IO rules use 3000-3999
NET rules use 4000-4999
MISC rules use 5000-5999
HIGHSYS rules use 6000-6999
HIGHLOAD rules use 7000-7999
HANG rules use 8000-8999

The naming convention is:
(SCHED|MEM|IO|NET|MISC|SYS|LOAD|HANG)_([0-9]+).py
SCHED_1xxx.py
MEM_2xxx.py
IO_3xxx.py
NET_4xxx.py
MISC_5xxx.py
HIGHSYS_6xxx.py
HIGHLOAD_7xxx.py
HANG_8xxx.py

Please add the rule ID in rule file name, and we also would like you
to add reproducers in osdh/ossre/repro folder named with rule ID.
"""
import sys, os, socket
import time,datetime
import json, base64, hashlib, re
import threading
import sched
import subprocess
import traceback

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
import collect_data
import crash
import utils

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

# Return one line to indentify this issue, this description will be
# displayed as a title for user to match the issue.
# Like "3.10: io hang in nvme盘"
def get_description():
    # SUBSYSTEM=SCHED|IO|MEM|NET|MISC|HIGHSYS|HIGHLOAD|HANG
    return '[NET]内核tcp_mem不足'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['sockets','tcp_mem','out of memory']

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

# Return some categories of this issue, these categories will be used by ossre.
# Available categories: ['HIGHSYS','HIGHLOAD','HANG','MEMLEAK','DEADLOCK','SOFTLOCKUP','CONFIG'
# 'HUNGTASK','RCUSTALL','DATA_CORRUPTION','RESOURCE_LEAK','REFERENCE_LEAK','NET_DROP'...]
def get_category():
    return ['CONFIG']

# Return whether this script need high CPU resource,
# like use 'search'|'foreach bt' in crash
def need_high_res():
    return False

# Return whether need input by user
def need_input():
    return False

# Return whether need long time to finish, like need some time to sample or sleep.
def need_long_time():
    return False

# Return whether need crash to attach /proc/kcore
def need_attach_crash():
    return False

# We define a fast mode which has suspected diagnosis to help fast scanning in ossre fast mode.
# You can have a accurate diagnosis by run this script directly.
def has_fast_mode():
    return True

def get_docker_socketstat(sn, data, dockerid, updated=0):
    if updated or dockerid not in data or 'socketstat' not in data[dockerid]:
        if 'dockercmd' not in data:
            cmd = 'which pouch 2>/dev/null'
            output = os.popen(cmd)
            ret = output.read()
            output.close()
            if len(ret) <= 0 or ret.find('which') >= 0:
                cmd = 'which docker 2>/dev/null'
                output = os.popen(cmd)
                ret = output.read()
                if len(ret) <= 0 or ret.find('which') >= 0:
                    data['dockercmd'] = ''
                else:
                    data['dockercmd'] = 'docker'
                output.close()
            else:
                data['dockercmd'] = 'pouch'

        data[dockerid] = {}
        data[dockerid]['socketstat'] = ''
        try:
            cmd = "%s exec -it %s bash -c 'cat /proc/net/sockstat'"%(data['dockercmd'],dockerid)
            output = os.popen(cmd)
            data[dockerid]['socketstat'] = output.read()
            output.close()
            if data[dockerid]['socketstat'].find('command not found') >= 0:
                data[dockerid]['socketstat'] = ''
        except:
            print( 'get_docker_socketstat exception!')
            data[dockerid]['socketstat'] = ''
    return data[dockerid]['socketstat']

def query(sn, data):
    try:
        ret = utils.get_script_result(sn,data)
        if ret:
            return ret

        ret = {}
        ret['return'] = False
        ret['solution'] = 'Not match'
        hotfix = ''

        dmesg = collect_data.get_dmesg(sn, data)

        if dmesg.find("TCP: out of memory -- consider tuning tcp_mem") < 0:
            utils.cache_script_result(sn,data,ret)
            print( __name__,':',ret)
            return ret

        cmd = "cat /proc/sys/net/ipv4/tcp_mem"
        tcp_mem = collect_data.get_cmddata(sn,data,cmd).strip()
        tcp_mem_max = tcp_mem.split()[2]
        
        cmd = "cat /proc/net/sockstat"
        socketstat = collect_data.get_cmddata(sn,data,cmd).strip()
        tcp_mem_now = 0
        if len(socketstat) > 0:
            socketstat = socketstat.splitlines()
            for line in socketstat:
                if "TCP:" in line:
                    tcp_mem_now = line.split('mem')[1]
                    break

            if int(tcp_mem_now) > int(tcp_mem_max)/4*3:
                dockerids = collect_data.get_dockerids(sn, data)
                if len(dockerids) <= 0:
                    utils.cache_script_result(sn,data,ret)
                    print( __name__,':',ret)
                    return ret
                for id in dockerids:
                    socketstat_dk = get_docker_socketstat(sn, data, id)
                    if len(socketstat_dk) <= 0:
                        continue
                    socketstat_dk = socketstat_dk.splitlines()
                    for line in socketstat:
                        if "TCP:" in line:
                            tcp_inuse_dk = line.split('inuse')[1].split()[0]
                            if int(tcp_inuse_dk) > int(tcp_mem_max)/4:
                                ret['return'] = True
                                ret['solution'] = utils.format_result(desc=("kernel: TCP: out of memory -- consider tuning tcp_mem"),
                                    solution=("docker(%s)使用超过tcp_mem_max/4，建议清理或增大tcp_mem_max"%(id)))
                                utils.cache_script_result(sn,data,ret)
                                print( __name__,':',ret)
                                return ret
                            break

        utils.cache_script_result(sn,data,ret)
        print( __name__,':',ret)
        return ret

    except Exception as e:
        traceback.print_exc()
        pass
    utils.cache_script_result(sn,data,ret)
    print( __name__,':',ret)
    return ret

def main():
    sn = ''
    data = {}
    ret = query(sn, data)
    if ret['return']:
        result = {os.path.basename(__file__)[:-3]:ret['solution']}
        utils.post_ossre_diag(json.dumps(result,ensure_ascii=False))

if __name__ == "__main__":
    main()
