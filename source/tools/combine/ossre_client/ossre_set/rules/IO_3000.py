# -*- coding: utf-8 -*-
# @Author: lichen

import sys, os, socket
import time,datetime
import json, base64, hashlib, re
import threading
import sched

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
import crash
import collect_data
import utils

# Return the severity level of the issue identified by this rule.
# Current support level: ('fatal','critical','error','warning','info')
# default is 'error'
def get_severe_level():
    return 'critical'

# Return one line to indentify this issue
# Like "3.10: io hang in nvme disk"
def get_description():
    return "[IO]3.10: io hang in nvme disk"

# Return some keywords of this issue
# Like "IO hang, nvme, 3.10, io util 100%, hung task, 大量D任务, load高"
def get_issue_keywords():
    return ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]

# Return some categories of this issue, these categories will be used by ossre.
# Available categories: ['HIGHSYS','HIGHLOAD','HANG','MEMLEAK','DEADLOCK','SOFTLOCKUP',
# 'HUNGTASK','RCUSTALL','DATA_CORRUPTION','RESOURCE_LEAK','REFERENCE_LEAK','NET_DROP'...]
def get_category():
    return ['HIGHLOAD','HANG','HUNGTASK']

# Return whether this script need high CPU resource,
# like use 'search'|'foreach bt' in crash
def need_high_res():
    return True

def need_attach_crash():
    return True

def has_fast_mode():
    return True

# We define a crash-only mode which can use crash-utility to analyze vmcore file.
def has_crashonly_mode():
    return False

# Reference: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=346c09f80459a3ad97df1816d6d606169a51001a
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

    cmd = 'find /sys/block/*/mq -name rq_list -print -exec cat {} \; | grep ffff'
    prev_request = collect_data.get_cmddata(sn, data, cmd, 1).strip().split()
    if len(prev_request) > 0:
        for i in range(2):
            time.sleep(1)
            request = collect_data.get_cmddata(sn, data, cmd, 1).strip().split()
            prev_request = utils.intersect_strings(prev_request, request)
    if len(prev_request) > 0:
        live_crash = collect_data.get_live_crash(sn, data)
        bio = live_crash.cmd("struct request.bio 0x%s"%(prev_request[0])).strip()
        if len(bio) > 0:
            bio = bio.split("=")[-1]
            if crash.valid_kernel_ptr(bio):
                bh = live_crash.cmd("struct bio.bi_private %s"%(bio))
                bh = bh.split("=")[-1]
                if crash.valid_kernel_ptr(bh):
                    bta = live_crash.cmd("foreach bt -f").splitlines()
                    pidstacks = crash.filter_all_btf_by_addr(bta, bh.strip()[2:])
                    if len(pidstacks) > 0:
                        for pid in pidstacks:
                            for func in pidstacks[pid]:
                                if 'io_schedule' in func:
                                    ret['return'] = True
                                    ret['solution'] = utils.format_result(commitid='https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=346c09f80459a3ad97df1816d6d606169a51001a')
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
