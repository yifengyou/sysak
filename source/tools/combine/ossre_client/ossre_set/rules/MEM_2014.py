# -*- coding: utf-8 -*-
# @Author: lichen

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
    return '[SUBSYSTEM]xxx'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['memory leak','kmalloc-32 leak','inotify_event_private_data leak','fsnotify_event_private_data leak']

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

# Return some categories of this issue, these categories will be used by ossre.
# Available categories: ['HIGHSYS','HIGHLOAD','HANG','MEMLEAK','DEADLOCK','SOFTLOCKUP',
# 'HUNGTASK','RCUSTALL','DATA_CORRUPTION','RESOURCE_LEAK','REFERENCE_LEAK','NET_DROP'...]
def get_category():
    return ['MEMLEAK']

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

def query(sn, data):
    try:
        ret = utils.get_script_result(sn,data)
        if ret:
            return ret

        run_all = os.environ.get('run_all')
        if run_all is None or int(run_all) != 1:
            return

        ret = {}
        ret['return'] = False
        ret['solution'] = 'Not match'

        live_crash = collect_data.get_live_crash(sn, data)
        for ops in ["inotify_fsnotify_ops","fanotify_fsnotify_ops"]:
            iops = live_crash.cmd("p &%s"%(ops)).strip()
            if len(iops) > 0 and ops in iops:
                iops = crash.extract_kernel_ptr(iops).strip()
                if len(iops) > 0:
                    search_k = live_crash.cmd("search -k %s"%(iops)).strip().splitlines()
                    for line in search_k:
                        counter = 0
                        q_len = 0
                        max_events = 0
                        line = line.split()[0][:-1].strip()
                        if line.endswith("08"):
                            line = line[:-1]+"0"
                            ngroup = live_crash.cmd("kmem %s"%(line)).strip()
                            if ("kmalloc-512" in ngroup and "[ALLOCATED]" in ngroup and
                                "[%s]"%(line) in ngroup):
                                refcnt = live_crash.cmd("struct fsnotify_group.refcnt %s"%(line)).strip().splitlines()
                                for tmp in refcnt:
                                    if "counter" in tmp:
                                        counter = int(tmp.strip().split()[-1])
                                q_lens = live_crash.cmd("struct fsnotify_group.q_len %s"%(line)).strip().splitlines()
                                for tmp in q_lens:
                                    if "q_len" in tmp:
                                        q_len = int(tmp.strip().split()[-1])
                                events = live_crash.cmd("struct fsnotify_group.max_events  %s"%(line)).strip().splitlines()
                                for tmp in events:
                                    if "max_events" in tmp:
                                        max_events = int(tmp.strip().split()[-1])
                            # we define that if the refcnt is larger than max_events*10, there should be a leakage.
                            if counter > max_events*10 and q_len < max_events:
                                ret['return'] = True
                                ret['solution'] = utils.format_result(desc=(
                                    "低版本内核fs/notify/notification.c:fsnotify_add_notify_event()存在内存泄漏!"))
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
    os.environ['run_slow']="1"
    ret = query(sn, data)
    if ret['return']:
        result = {os.path.basename(__file__)[:-3]:ret['solution']}
        utils.post_ossre_diag(json.dumps(result,ensure_ascii=False))

if __name__ == "__main__":
    main()
