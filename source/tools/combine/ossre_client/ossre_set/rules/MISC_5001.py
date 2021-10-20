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
    return "warning"

# Return one line to indentify this issue, this description will be
# displayed as a title for user to match the issue.
# Like "3.10: io hang in nvme盘"
def get_description():
    return '[MISC]3.10内核:CPU核数识别异常'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['CPU核数','CPU核数识别异常','3.10内核']

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

# Return some categories of this issue, these categories will be used by ossre.
# Available categories: ['HIGHSYS','HIGHLOAD','HANG','MEMLEAK','DEADLOCK','SOFTLOCKUP','CONFIG'
# 'HUNGTASK','RCUSTALL','DATA_CORRUPTION','RESOURCE_LEAK','REFERENCE_LEAK','NET_DROP'...]
def get_category():
    return ['CONFIG']

#Reference: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=947134d9b00f342415af7eddd42a5fce7262a1b9
def query(sn, data):
    ret = utils.get_script_result(sn,data)
    if ret:
        return ret

    ret = {}
    ret['return'] = False
    ret['solution'] = 'Not match'

    dmesg = collect_data.get_dmesg(sn, data)
    if len(dmesg) <= 0:
        utils.cache_script_result(sn,data,ret)
        return ret

    if (re.search("CPU \d+ APICId \d+ disabled", dmesg)):
        ret['return'] = True
        ret['solution'] = utils.format_result(desc=('CPU核数识别异常'),
             commitid=('https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=947134d9b00f342415af7eddd42a5fce7262a1b9'),
             added=('The fix can not be patched as a hotfix, please upgrade your kernel instead.'))

    utils.cache_script_result(sn,data,ret)
    print( __name__,':',ret)
    return ret

def main():
    sn = ''
    data = {}
    ret = query(sn, data)
    print( __name__,':',ret)
    if ret['return']:
        result = {os.path.basename(__file__)[:-3]:ret['solution']}
        utils.post_ossre_diag(json.dumps(result,ensure_ascii=False))

if __name__ == "__main__":
    main()
