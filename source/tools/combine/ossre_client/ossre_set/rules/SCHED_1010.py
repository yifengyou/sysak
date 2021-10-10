# -*- coding: utf-8 -*-
# @Author: shiyan

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
import os.path

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
    return '[SCHED]systemd too many cgroups in systemd.slice'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['memcg','systemd','systemd.slice',
        'leakage','cgroup']

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

def get_category():
    return 'systemd'

CGROUP_SUB = ['cpu', 'memory', 'cpuset', 'blkio']

#Reference: https://github.com/poettering/systemd/commit/e1e98911a818ad3b46c6a1c26d759df590bef476

def query(sn, data):
    ret = utils.get_script_result(sn,data)
    if ret:
        return ret

    ret = {}
    ret['return'] = False
    ret['solution'] = 'Not match'

    try:
        hotfix_all = collect_data.get_hotfix_info(sn, data)
        maxcg = 0
        for subsys in CGROUP_SUB:
            path = "/sys/fs/cgroup/%s"%subsys
            
            if os.path.exists(path):
                path = "%s/system.slice"%path
                if os.path.exists(path):
                    cmd = "ls %s |grep mount |wc -l"%path
                    cgnum = collect_data.get_cmddata(sn, data, cmd)
                    cgnum = int(cgnum)
                    if cgnum > maxcg:
                        maxcg = cgnum

        if maxcg >= 1000:
            ret['return'] = True
            ret['solution'] = utils.format_result(desc=('systemd has too many cgroups in systemd.slice'),
                commitid=('https://github.com/poettering/systemd/commit/e1e98911a818ad3b46c6a1c26d759df590bef476'))
 
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
