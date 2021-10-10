# -*- coding: utf-8 -*-
# @Author: tuquan

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

#Reference: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=54ab49fde95605a1077f759ce454d94e84b5ca45

# Return the severity level of the issue identified by this rule.
# Current support level: ('fatal','critical','error','warning','info')
# default is 'error'
def get_severe_level():
    return "critical"

def query(sn, data):
    ret = utils.get_script_result(sn,data)
    if ret:
        return ret

    ret = {}
    ret['return'] = True
    ret['solution'] = utils.format_result(desc=("rmmod nf_conntrack hang forever"),
        commitid=("https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=54ab49fde95605a1077f759ce454d94e84b5ca45"))

    cmd1 = 'ps -elf | grep "rmmod nf_conn" | grep -v grep | head -n 1 | awk \'{print $4}\''
    pid = collect_data.get_cmddata(sn,data,cmd1).strip()
    if pid == "":
        ret['return'] = False
        ret['solution'] = 'Not match'
        utils.cache_script_result(sn,data,ret)
        print( __name__,':',ret)
        return ret

    cmd2 = 'top -b -p '+pid+' -n 1 | grep PID -A1 | tail -n 1 | awk \'{print $(NF-3)}\''
    cpu_usage = collect_data.get_cmddata(sn,data,cmd2).strip()
    cpu_usage = float(cpu_usage)
    print( "cpu_usage : ",cpu_usage)
    if cpu_usage < 20 :
        ret['return'] = False
        ret['solution'] = 'Not match'
        utils.cache_script_result(sn,data,ret)
        print( __name__,':',ret)
        return ret

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
