# -*- coding: utf-8 -*-
# @Author: xxx

"""
We define a unique ID for every rule,
SCHED rules use 1000-1999
MEM rules use 2000-2999
IO rules use 3000-3999
NET rules use 4000-4999
MISC rules use 5000-5999
HIGHSYS rules use 6000-6999
HIGHLOAD rules use 7000-7999
HANG rules use 8000-8999

The naming convention is:
(SCHED|MEM|IO|NET|MISC|SYS|LOAD|HANG)_([0-9]+).py
SCHED_1xxx.py
MEM_2xxx.py
IO_3xxx.py
NET_4xxx.py
MISC_5xxx.py
HIGHSYS_6xxx.py
HIGHLOAD_7xxx.py
HANG_8xxx.py

Please add the rule ID in rule file name, and we also would like you
to add reproducers in osdh/ossre/repro folder named with rule ID.
"""
import sys, os, socket
import time,datetime
import json, base64, hashlib, re
import threading
import sched
import subprocess
import traceback

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
import collect_data
import crash
import utils

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

'''
Please add reproducing steps here to help test this script, like:
Reproduce:
1. create a docker by docker run -d xxx
2. delete the WorkDir of this docker in host, use docker inspect $dockerid | grep 'WorkDir'
3. shell in thie docker by "docker exec -it $dockerid bash" and echo y | rm /etc/host.conf, will get like
   "rm: cannot remove ‘/etc/host.conf’: No such file or directory".
'''

# Return category of this rule
# Current support category: ('memleak','highload','highsys',
# 'highiowait','highnetretran')
def get_category():
    return ''

# Return the severity level of the issue identified by this rule.
# Current support level: ('fatal','critical','error','warning','info')
# generally, hardware error is fatal, crash and hang is critical, and
# default level is error.
def get_severe_level():
    return 'error'

# Return one line to indentify this issue, this description will be
# displayed as a title for user to match the issue.
# Like "3.10: io hang in nvme盘"
def get_description():
    # SUBSYSTEM=SCHED|IO|MEM|NET|MISC|HIGHSYS|HIGHLOAD|HANG
    return '[SUBSYSTEM]xxx'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['','']

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

# Return whether this script need high CPU resource,
# like use 'search'|'foreach bt' in crash
def need_high_res():
    return False

# Return whether need input by user
def need_input():
    return False

# Return whether need long time to finish, like need some time to sample or sleep.
def need_long_time():
    return False

# Return whether need crash to attach /proc/kcore
def need_attach_crash():
    return False

# We define a crash-only mode which can use crash-utility to analyze vmcore file.
def has_crashonly_mode():
    return False

#Reference: http://xxx
def query(sn, data):
    try:
        ret = utils.get_script_result(sn,data)
        if ret:
            return ret

        ret = {}
        ret['return'] = False
        ret['solution'] = 'Not match'
        hotfix = ''

    except Exception as e:
        traceback.print_exc()
        pass

    run_silent = os.environ.get('run_silent')
    if run_silent is None or int(run_silent) != 1:
        print(__name__,':',ret)
    utils.cache_script_result(sn,data,ret)

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
