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

# Return one line to indentify this issue, this description will be
# displayed as a title for user to match the issue.
# Like "3.10: io hang in nvme盘"
def get_description():
    return '[systemd]systemd内存泄漏'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['systemd','systemd 内存泄漏']

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

def get_category():
    return 'systemd'

def query(sn, data):
    ret = utils.get_script_result(sn,data)
    if ret:
        return ret

    ret = {}
    ret['return'] = False
    ret['solution'] = "Not match"

    # Check memory leakage
    vmrss = collect_data.get_cmddata(sn, data, "cat /proc/1/status | grep VmRSS | awk '{print $2}'")
    try:
        vmrss = int(vmrss)
        if vmrss > 2000000:
            ret['return'] = True
            ret['solution'] = utils.format_result(desc=(
                    "systemd used more than 2G memory, it may have memory leak."),
                    solution=("Please upgrade systemd to latest version,\n"
                    " you can run 'sudo systemctl daemon-reexec' as a temp workaround."))
    except:
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
