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
    return "error"

# Return one line to indentify this issue, this description will be
# displayed as a title for user to match the issue.
# Like "3.10: io hang in nvme盘"
def get_description():
    return '[MISC]agetty CPU 100%问题'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['agetty','CPU 100%问题']

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

# Return some categories of this issue, these categories will be used by ossre.
# Available categories: ['HIGHSYS','HIGHLOAD','HANG','MEMLEAK','DEADLOCK','SOFTLOCKUP',
# 'HUNGTASK','RCUSTALL','DATA_CORRUPTION','RESOURCE_LEAK','REFERENCE_LEAK','NET_DROP'...]
def get_category():
    return ['HANG']

#Fix: https://git.kernel.org/pub/scm/utils/util-linux/util-linux.git/commit/term-utils/agetty.c?id=d23597a88cdbdbc7f2a1c84cd6fe0b2ad9f7e87b
def query(sn, data):
    ret = utils.get_script_result(sn,data)
    if ret:
        return ret

    ret = {}
    ret['return'] = False
    ret['solution'] = 'Not match'
    hotfix = ''

    top = collect_data.get_top_info(sn, data, 1)
    if len(top) <= 0:
        utils.cache_script_result(sn,data,ret)
        print( __name__,':',ret)
        return ret

    top = top.splitlines()
    pos = int(-1)
    for line in top:
        if line.find('%CPU') >= 0:
            line = line.strip().split()
            count = 0
            for item in line:
                if item == '%CPU':
                    pos = count
                    break
                count += 1
            continue
        if line.find('agetty') >= 0 and pos != -1:
            line = line.strip().split()
            if float(line[pos]) > float(90):
               ret['return'] = True
               ret['solution'] = utils.format_result(cause=('agetty consumes too much CPU exceptionally'),
                       solution=('please try to upgrade util-linux to '
                       'util-linux-2.23.2-61.1.alios7 or newer version.'
                       ' "systemctl restart getty@tty1" as workaround.'),
                       commitid=('https://git.kernel.org/pub/scm/utils/util-linux/util-linux.git/commit/term-utils/agetty.c?id=d23597a88cdbdbc7f2a1c84cd6fe0b2ad9f7e87b'))
               break 

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
