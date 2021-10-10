# -*- coding: utf-8 -*-
# @Author: shiyan

import os
import sys
import time
import subprocess
import re
import json
from time import sleep
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

# Return one line to indentify this issue
# Like "3.10: io hang in nvme disk"
def get_description():
    return "[SCHED]3.10: min_vruntime 计数溢出"

# Return some keywords of this issue
# Like "load高, 4.09, cpu util 100%, softlockup, 大量D任务, load高"
def get_issue_keywords():
    return [ "3.10", "min_vruntime", "vruntime", "cpu调度" ]

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ["min_vruntime", "vruntime", "cpu调度"]

# Return whether this script need high CPU resource, like use search in crash
def need_high_res():
    return False

# Return whether need input by user
def need_input():
    return False

# Return whether need long time to finish
def need_long_time():
    return True

def query(sn, data):
    ret = utils.get_script_result(sn,data)
    if ret:
        return ret

    ret = {}
    ret['return'] = False
    ret['solution'] = 'Not match'
    hotfix = ''

    check_num = 0
    for i in range(5):
        cmd = 'ret=$(cat /proc/sched_debug | grep \'cfs_rq\[[0-9]*\]:/$\' -A3 | grep min_vruntime | awk \'BEGIN{flag=0}{if ($3<0) flag=1}END{print flag}\'); if [[ \"$ret\" -eq 1 ]]; then echo \"overflow\"; fi;'
        output = os.popen(cmd)
        result = output.read()
        output.close()
        if 'overflow' in result:
            check_num += 1
        sleep(1)

    if check_num > 0:
        ret['return'] = True
        ret['solution'] = utils.format_result(desc=("min_vruntime 计数溢出"))

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
