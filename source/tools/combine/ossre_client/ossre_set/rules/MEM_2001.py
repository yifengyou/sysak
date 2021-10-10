# -*- coding: utf-8 -*-
# @Author: shiyan

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

#Reference: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=4d1ceea8516cd6adf21f6b75995e2a7d4f376f9b

# Return the severity level of the issue identified by this rule.
# Current support level: ('fatal','critical','error','warning','info')
# default is 'error'
def get_severe_level():
    return 'error'

# Return one line to indentify this issue
# Like "3.10: io hang in nvme disk"
def get_description():
    return "[MEM]4.9: ethtool持续申请高阶内存失败"

# Return some keywords of this issue
# Like "load高, 4.09, cpu util 100%, softlockup, 大量D任务, load高"
def get_issue_keywords():
    return ["ethtool", "dev_ethtool", "page allocation failure", "OOM"]

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ["OOM",  "page allocation failure"]

# Return whether this script need high CPU resource, like use search in crash
def need_high_res():
    return False

# Return whether need input by user
def need_input():
    return False

# Return whether need long time to finish
def need_long_time():
    return False

def query(sn, data):
    ret = utils.get_script_result(sn,data)
    if ret:
        return ret

    ret = {}
    ret['return'] = False
    ret['solution'] = 'Not match'
    hotfix = ''

    dmesg = collect_data.get_dmesg(sn, data)
    if len(dmesg) <= 0:
        utils.cache_script_result(sn,data,ret)
        print( __name__,':',ret)
        return ret
    if (dmesg.find('ethtool: page allocation failure: order:') >= 0 and dmesg.find('__alloc_pages_nodemask') >= 0) :
        ret['return'] = True
        ret['solution'] = utils.format_result(cause="疑似已知问题，请参考社区补丁:https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=4d1ceea8516cd6adf21f6b75995e2a7d4f376f9b")

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
