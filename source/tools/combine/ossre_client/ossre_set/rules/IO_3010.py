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
    return '[IO]dput softlockup'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['softlockup','3.10','dput']

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

# Return some categories of this issue, these categories will be used by ossre.
# Available categories: ['HIGHSYS','HIGHLOAD','HANG','MEMLEAK','DEADLOCK','SOFTLOCKUP',
# 'HUNGTASK','RCUSTALL','DATA_CORRUPTION','RESOURCE_LEAK','REFERENCE_LEAK','NET_DROP'...]
def get_category():
    return ['HANG','SOFTLOCKUP']

#Reference: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=47be61845c775643f1aa4d2a54343549f943c94c

def query(sn, data):
    ret = utils.get_script_result(sn,data)
    if ret:
        return ret

    ret = {}
    ret['return'] = False
    ret['solution'] = 'Not match'

    try:
        dmesg = collect_data.get_dmesg(sn, data)
        softlockup_cts = collect_data.extract_softlockup_calltrace(sn, dmesg, data)
        if len(softlockup_cts) > 0:
            for ct in softlockup_cts:
                if "dput" in ct["softlockupkey"]:
                    ret['return'] = True
                    ret['solution'] = utils.format_result(cause=("疑似已知问题，请参考社区补丁:"
                       "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=346c09f80459a3ad97df1816d6d606169a51001a"))
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
