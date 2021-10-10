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

# Return one line to indentify this issue, this description will be
# displayed as a title for user to match the issue.
# Like "3.10: io hang in nvme盘"
def get_description():
    return '[IO]fsnotify soft lockup'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['soft lockup','fsnotify', 'ulogfs_mon']

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

# Reference: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=d90a10e2444ba5a351fa695917258ff4c5709fa5
def query(sn, data):
    ret = utils.get_script_result(sn,data)
    if ret:
        return ret

    ret = {}
    ret['return'] = False
    ret['solution'] = 'Not match'

    try:
        dmesg = collect_data.get_dmesg(sn, data)
        version = collect_data.get_kernel_version(sn, data)
        if (dmesg.find("BUG: soft lockup") > 0 and 
            dmesg.find("] __fsnotify_parent+0x") >= 0 and
            dmesg.find("] fsnotify+0x") >= 0):
            ret['return'] = True
            ret['solution'] = utils.format_result(cause="疑似已知问题，请参考社区补丁:https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=d90a10e2444ba5a351fa695917258ff4c5709fa5")
    except Exception as e:
        print( __name__,e)
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
