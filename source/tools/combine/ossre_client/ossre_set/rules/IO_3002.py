# -*- coding: utf-8 -*-
# @Author: lichen

"""
We define a unique ID for every rule,
SCHED rules use 1000-1999
MEM rules use 2000-2999
IO rules use 3000-3999
NET rules use 4000-4999
MISC rules use 5000-5999

The naming convention is:
(SCHED|MEM|IO|NET|MISC)_([0-9]+).py
SCHED_1xxx.py
MEM_2xxx.py
IO_3xxx.py
NET_4xxx.py
MISC_5xxx.py

Please add the rule ID in rule file name, and we also would like you
to add reproducers in osdh/ossre/repro folder named with rule ID.
"""

import os
import sys
import time
import subprocess
import re
import json

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
import collect_data
import crash
import utils

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

# Return the severity level of the issue identified by this rule.
# Current support level: ('fatal','critical','error','warning','info')
# default is 'error'
def get_severe_level():
    return 'critical'

# Return one line to indentify this issue
# Like "3.10: io hang in nvme disk"
def get_description():
    return "[IO]jbd2 hang"

# Return some keywords of this issue, key error dmesgs
# Like "IO hang, nvme, 3.10, io util 100%, hung task, 大量D任务, load高"
def get_issue_keywords():
    return ["jbd2 hang", "hung task", "大量D任务", "load高","blocked for more than 120 seconds"]

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ["jbd2 hang","jbd2死锁"]

# Return some categories of this issue, these categories will be used by ossre.
# Available categories: ['HIGHSYS','HIGHLOAD','HANG','MEMLEAK','DEADLOCK','SOFTLOCKUP',
# 'HUNGTASK','RCUSTALL','DATA_CORRUPTION','RESOURCE_LEAK','REFERENCE_LEAK','NET_DROP'...]
def get_category():
    return ['HIGHLOAD','HANG','DEADLOCK']

# Return whether need crash to attach /proc/kcore
def need_attach_crash():
    return True

# Return whether has a fast mode to run, if True, this script
# can be included in fast mode by process_engine.py.
def has_fast_mode():
    return True

def query(sn, data):
    ret = utils.get_script_result(sn,data)
    if ret:
        return ret

    run_all = os.environ.get('run_all')
    if run_all is None or int(run_all) != 1:
        return

    ret = {}
    ret['return'] = False
    ret['solution'] = 'Not match'

    crash_inst = collect_data.get_live_crash(sn, data)
    ps_jbd2 = crash_inst.cmd("ps -k").strip()
    if len(ps_jbd2) <= 0:
        print( __name__,':',ret)
        return ret
    ps_jbd2 = ps_jbd2.splitlines()
    jbd2_list = []
    jbd2_commit = []
    jbd2_ckpt = []
    for ps in ps_jbd2:
        ps = ps.strip()
        if ps.find('jbd2/') > 0 and ps.find('UN') > 0:
            jbd2_commit.append(ps)
        if ps.find('jbd2-ckpt/') > 0 and ps.find('UN') > 0:
            jbd2_ckpt.append(ps)
    if len(jbd2_ckpt) <= 0:
        print( __name__,':',ret)
        return ret
    for ckpt in jbd2_ckpt:
        ckpt = ckpt.strip().split()
        ckpt_name = ckpt[-1]
        index = ckpt_name.rindex('/')
        if index < 0:
            continue
        ckpt_name = ckpt_name[index+1:-1]
        for commit in jbd2_commit:
            if commit.find(ckpt_name) > 0:
                commit = commit.strip().split()
                ckpt_pid = ckpt[0]
                commit_pid = commit[0]
                pids = [commit_pid,ckpt_pid]
                jbd2_list.append(pids)
    for item in jbd2_list:
        jbd2_commit = item[0]
        jbd2_ckpt = item[1]
        commit_task = crash_inst.cmd('task %s'%(jbd2_commit)).strip()
        if len(commit_task) <= 0:
            continue
        cpu = -1
        last_arrival = -1
        commit_task = commit_task.splitlines()
        for line in commit_task:
            line = line.strip()
            if cpu == -1 and line.find('cpu =') == 0:
                cpu = int(line.split('=')[-1][:-1])
            elif line.find('last_arrival =') == 0:
                last_arrival = long(line.split('=')[-1][:-1])
            if cpu != -1 and last_arrival != -1:
                break
        if cpu == -1 or last_arrival == -1:
            continue
        clock = 0
        cmd = "p runqueues:%s | grep 'clock ='"%(cpu)
        rq_clock = crash_inst.cmd(cmd).strip()
        if len(rq_clock) <= 0:
            continue
        rq_clock = rq_clock.splitlines()
        for line in rq_clock:
            line = line.strip()
            if line.find('clock =') == 0:
                clock = long(line.split('=')[-1][:-1])
                break
        if clock <= 0 or last_arrival <= 0 or (clock - last_arrival) < long(600000000000):
            continue

        ckpt_task = crash_inst.cmd('task %s'%(jbd2_ckpt)).strip()
        if len(ckpt_task) <= 0:
            continue
        cpu = -1
        last_arrival = -1
        ckpt_task = ckpt_task.splitlines()
        for line in ckpt_task:
            line = line.strip()
            if cpu == -1 and line.find('cpu =') == 0:
                cpu = int(line.split('=')[-1][:-1])
            elif line.find('last_arrival =') == 0:
                last_arrival = long(line.split('=')[-1][:-1])
            if cpu != -1 and last_arrival != -1:
                break
        if cpu == -1 or last_arrival == -1:
            continue
        clock = 0
        rq_clock = crash_inst.cmd("p runqueues:%s | grep 'clock ='"%(cpu)).strip()
        if len(rq_clock) <= 0:
            continue
        rq_clock = rq_clock.splitlines()
        for line in rq_clock:
            line = line.strip()
            if line.find('clock =') == 0:
                clock = long(line.split('=')[-1][:-1])
                break
        if clock <= 0 or last_arrival <= 0 or (clock - last_arrival) < long(600000000000):
            continue

        bt_commit = crash_inst.cmd('bt -f %s'%(jbd2_commit)).strip()
        bt_ckpt = crash_inst.cmd('bt -f %s'%(jbd2_ckpt)).strip()
        if len(bt_commit) <=0 or len(bt_ckpt) <= 0:
            continue
        if bt_commit.find('__mutex_lock_slowpath') < 0:
            continue
        if bt_ckpt.find('jbd2_log_wait_commit') < 0:
            continue
        bt_commit = bt_commit.splitlines()
        bt_addr = []
        reach_mutex = 0
        for line in bt_commit:
            line = line.strip()
            if line.find('__mutex_lock_slowpath') >= 0:
                reach_mutex = 1
            elif reach_mutex == 1 and line.find('mutex_lock at') >= 0:
                break
            elif reach_mutex == 1:
                index = line.index(':')
                line = line[index+1:].strip().split()
                for addr in line:
                    bt_addr.append(addr)
        if len(bt_addr) < 6:
            continue
        mutex = bt_addr[-6]
        if not crash.valid_kernel_ptr('0x%s'%(mutex)):
            continue
        owner = crash_inst.cmd('struct mutex.owner 0x%s'%(mutex)).strip()
        if len(owner) <= 0 or owner.find('owner =') < 0:
            continue
        owner = owner.split('=')[-1].strip()
        if not crash.valid_kernel_ptr(owner):
            continue
        bt_mutex = crash_inst.cmd('bt -f %s'%(owner))
        if len(bt_mutex) <= 0 or bt_mutex.find('jbd2_log_wait_for_space') < 0:
            continue
        ret['return'] = True
        ret['solution'] = utils.format_result(commitid='https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=53cf978457325d8fb2cdecd7981b31a8229e446e')
        break

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
