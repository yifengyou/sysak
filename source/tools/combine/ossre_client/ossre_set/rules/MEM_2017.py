# -*- coding: utf-8 -*-
# @Author: changjun

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

'''
Please add reproducing steps here to help test this script, like:
Reproduce:
1. create a docker by docker run -d xxx
2. delete the WorkDir of this docker in host, use docker inspect $dockerid | grep 'WorkDir'
3. shell in thie docker by "docker exec -it $dockerid bash" and echo y | rm /etc/host.conf, will get like
   "rm: cannot remove ‘/etc/host.conf’: No such file or directory".
'''

# Return some categories of this issue, these categories will be used by ossre.
# Available categories: ['HIGHSYS','HIGHLOAD','HANG','MEMLEAK','DEADLOCK','SOFTLOCKUP',
# 'HUNGTASK','RCUSTALL','DATA_CORRUPTION','RESOURCE_LEAK','REFERENCE_LEAK','NET_DROP'...]
def get_category():
    return ['MEMLEAK','HANG']

# Return one line to indentify this issue, this description will be
# displayed as a title for user to match the issue.
# Like "3.10: io hang in nvme盘"
def get_description():
    # SUBSYSTEM=SCHED|IO|MEM|NET|MISC|HIGHSYS|HIGHLOAD|HANG
    return '[MEM]slab'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['memory leak','dentry','SReclaimable','slab']

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

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

def build_ret_value(sn, data, ret):
    ret['return'] = True
    ret['solution'] = utils.format_result(cause="s_nr_dentry_unused溢出为负数导致prune_supper无法回收dentry和inode导致内存泄漏,参考社区补丁:3942c07ccf98e66b8893f396dca98f5b076f905f")
    utils.cache_script_result(sn,data,ret)
    print_ret(ret)
    return ret

def print_ret(ret):
    print(__name__,':',json.dumps(ret, ensure_ascii=False))

def build_ret_none(sn, data, ret):
    utils.cache_script_result(sn,data,ret)
    print_ret(ret)
    return ret

def query(sn, data):
    try:
        ret = utils.get_script_result(sn,data)
        if ret:
            return ret

        ret = {}
        ret['return'] = False
        ret['solution'] = 'Not match'
        dentry_state = collect_data.get_procfs_value(sn,
            data, "/proc/sys/fs/dentry-state").strip().split()
        dentry_state = int(dentry_state[1])
        if (dentry_state < 0):
            return build_ret_value(sn, data, ret)
        else:
            return build_ret_none(sn, data, ret) 
    except Exception as e:
        traceback.print_exc()
        pass
    return build_ret_none(sn, data, ret)

def main():
    sn = ''
    data = {}
    ret = query(sn, data)
    if ret['return']:
        result = {os.path.basename(__file__)[:-3]:ret['solution']}
        utils.post_ossre_diag(json.dumps(result, encoding="UTF-8", ensure_ascii=False))

if __name__ == "__main__":
    main()
