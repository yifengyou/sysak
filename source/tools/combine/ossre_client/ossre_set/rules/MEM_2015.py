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

# Return category of this rule
# Current support category: ('memleak','highload','highsys',
# 'highiowait','highnetretran')
def get_category():
    return 'memleak'

# Return one line to indentify this issue, this description will be
# displayed as a title for user to match the issue.
# Like "3.10: io hang in nvme盘"
def get_description():
    # SUBSYSTEM=SCHED|IO|MEM|NET|MISC|HIGHSYS|HIGHLOAD|HANG
    return '[SUBSYSTEM]xxx'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['memory leak','kmalloc-64 leak','kmalloc-128 leak','rcu']

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

# Return whether this script need high CPU resource,
# like use 'search'|'foreach bt' in crash
def need_high_res():
    return True

# Return whether need input by user
def need_input():
    return False

# Return whether need long time to finish, like need some time to sample or sleep.
def need_long_time():
    return True

# Return whether need crash to attach /proc/kcore
def need_attach_crash():
    return True

# We define a fast mode which has suspected diagnosis to help fast scanning in ossre fast mode.
# You can have a accurate diagnosis by run this script directly.
def has_fast_mode():
    return True

def get_rcu_log():
    dmesg = collect_data.get_dmesg(sn, data)
    if len(dmesg) <= 0:
        return False
    if dmesg.find("synchronize_sched") >= 0:
        return True
    return False

def build_ret_value(sn, data, ret):
    ret['return'] = True
    ret['solution'] = utils.format_result(cause="内核rcu线程长时间没有被唤醒，会导致大量slub不能通过rcu线程回收导致大量内存泄漏!")
    utils.cache_script_result(sn,data,ret)
    print_ret(ret)
    return ret

def print_ret(ret):
    print(__name__,':',json.dumps(ret, ensure_ascii=False))

def query(sn, data):
    try:
        ret = utils.get_script_result(sn,data)
        if ret:
            return ret

        run_slow = os.environ.get('run_slow')
        if run_slow is None or int(run_slow) != 1:
            return

        ret = {}
        ret['return'] = False
        ret['solution'] = 'Not match'
        kmall64_num = collect_data.get_sysfs_value(sn,
            data, "/sys/kernel/slab/kmalloc-64/objects").strip().split()[0]
        kmall64_num = int(kmall64_num)
        #if (kmall64_num > 200000000) and get_rcu_log():
        #    if run_fast:
        #        return build_ret_value(sn, data, ret)
        live_crash = collect_data.get_live_crash(sn, data)
        ts = live_crash.cmd("ps -l 2").strip().split(' ')[0][1:-1]
        ts = int(ts)
        rcuos = live_crash.cmd("ps -l | grep rcuos").strip().split('\n')
        for rcu_thread in rcuos:
              rcu_ts = rcu_thread.strip().split(' ')[0][1:-1]
              rcu_ts = int(rcu_ts)
              if ((ts - rcu_ts) >> 30) >= 1800:
                   return build_ret_value(sn, data, ret)
    except Exception as e:
        traceback.print_exc()
        pass
    utils.cache_script_result(sn,data,ret)
    print_ret(ret)
    return ret

def main():
    sn = ''
    data = {}
    os.environ['run_slow']="1"
    ret = query(sn, data)
    if ret['return']:
        result = {os.path.basename(__file__)[:-3]:ret['solution']}
        utils.post_ossre_diag(json.dumps(result, encoding="UTF-8", ensure_ascii=False))

if __name__ == "__main__":
    main()
