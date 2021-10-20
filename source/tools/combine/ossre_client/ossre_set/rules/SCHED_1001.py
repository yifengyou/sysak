# -*- coding: utf-8 -*-
# @Author: lichen

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
    return "critical"

# Return one line to indentify this issue, this description will be
# displayed as a title for user to match the issue.
# Like "3.10: io hang in nvme盘"
def get_description():
    return '[SCHED]pouch exec 和pouch stop卡住未退出,cgroup的freezer.state一直处于FREEZING状态'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['pouch exec 和pouch stop卡住','freezer.state一直处于FREEZING状态','runc exec进程和runc kill 进程卡住']

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

# Return some categories of this issue, these categories will be used by ossre.
# Available categories: ['HIGHSYS','HIGHLOAD','HANG','MEMLEAK','DEADLOCK','SOFTLOCKUP','CONFIG'
# 'HUNGTASK','RCUSTALL','DATA_CORRUPTION','RESOURCE_LEAK','REFERENCE_LEAK','NET_DROP'...]
def get_category():
    return ['HANG']

# Return whether this script need high CPU resource,
# like use 'search'|'foreach bt' in crash
def need_high_res():
    return True

# Return whether need crash to attach /proc/kcore
def need_attach_crash():
    return True

# Return whether has a fast mode to run, if True, this script
# can be included in fast mode by process_engine.py.
def has_fast_mode():
    return True

# Reference: https://github.com/cloudfoundry/garden-runc-release/issues/121
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
    hotfix = ''

    cmd = 'ps -eL -o pid,lwp,stat,comm'
    output = os.popen(cmd)
    task_msg = output.read().splitlines()
    output.close()

    task_D = []
    for line in task_msg:
        line = line.strip()
        item = line.split()
        if item[0] not in 'PID':
            if 'D' in item[2]:
                task_D.append(item[0])

    if len(list(task_D)) == 0:
        utils.cache_script_result(sn,data,ret)
        print( __name__,':',ret)
        return ret

    task_func = []
    for pid in task_D:
        path = "/proc/%s/stack"%pid
        if os.path.isfile(path):
            cmd = "cat %s 2>/dev/null"%path
            output = os.popen(cmd)
            task_stack = output.read()
            output.close()
            if 'flush_old_exec' in task_stack:
                task_func.append(pid)
                continue

    if len(list(task_func)) == 0:
        utils.cache_script_result(sn,data,ret)
        print( __name__,':',ret)
        return ret

    crash_inst = collect_data.get_live_crash(sn, data)
    pidbts = {}
    for pid in task_func:
        cmd = "bt %s"%pid
        pid_stack =  crash_inst.cmd(cmd)
        if len(pid_stack) == 0:
            continue
        pid_stack = pid_stack.strip().splitlines()
        pidbts[pid] = pid_stack

    if len(pidbts) <= 0:
        utils.cache_script_result(sn,data,ret)
        print( __name__,':',ret)
        return ret

    for pid in pidbts:
        pattern = re.compile(r'PID:.*TASK:\s+(fff[0-9a-f]+)\s+.*')
        match = pattern.match(pidbts[pid][0])
        if not match:
            continue
        task = match.group(1)
        cgroups = crash_inst.cmd('struct task_struct.cgroups %s'%(task))
        if len(cgroups) <= 0 or cgroups.find('cgroups') < 0:
            continue
        cgroups = cgroups.strip().split('=')[1].strip()
        cgroups = cgroups.strip().split()[0]
        subsys = crash_inst.cmd('struct css_set.subsys %s'%(cgroups))
        if len(subsys) <= 0 or subsys.find('subsys') <= 0:
            continue
        subsys = subsys.strip()[subsys.find('{')+1:subsys.find('}')].split(',')
        for item in subsys:
            item = item.strip().split()[0]
            freezer = crash_inst.cmd('struct freezer %s'%(item))
            if len(freezer) <= 0 or freezer.find('freezer_cgrp_subsys') < 0:
                continue
            freezer = freezer.splitlines()
            state = freezer[-2]
            if state.find('state') < 0:
                state = crash_inst.cmd('struct freezer.state %s'%(item))
            if len(state) <= 0 or state.find('state') < 0:
                continue
            state = int(state.strip().split('=')[1])
            # CGROUP_FREEZING_SELF    = (1 << 1), /* this freezer is freezing */
            # CGROUP_FREEZING_PARENT    = (1 << 2), /* the parent freezer is freezing */
            # CGROUP_FREEZING     = CGROUP_FREEZING_SELF | CGROUP_FREEZING_PARENT
            if state & int(0x1|0x2):
                ret['return'] = True
                ret['solution'] = utils.format_result(desc=('docker exec&docker stop hang'),
                    solution=('PID %s tries to kill its thread group but this group '
                    'is being freezing and hang, you need to kill -9 %s to unfreeze\n'%(pid, pid)))
                break
        if ret['return']:
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
