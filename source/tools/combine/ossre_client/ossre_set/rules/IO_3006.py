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

'''
Reproduce:
1. create a docker by docker run -d xxx
2. delete the WorkDir of this docker in host, use docker inspect $dockerid | grep 'WorkDir'
3. shell in thie docker by "docker exec -it $dockerid bash" and echo y | rm /etc/host.conf, will get like
   "rm: cannot remove ‘/etc/host.conf’: No such file or directory".
'''

# Return the severity level of the issue identified by this rule.
# Current support level: ('fatal','critical','error','warning','info')
# default is 'error'
def get_severe_level():
    return 'error'

# Return one line to indentify this issue, this description will be
# displayed as a title for user to match the issue.
# Like "3.10: io hang in nvme盘"
def get_description():
    return '[IO]容器内删除或者创建文件报No such file or directory错误'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['bash: cannot create temp file for here-document: No such file or directory','ENOENT (No such file or directory)']

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

# Return whether need input by user
def need_input():
    return True

def query(sn, data):
    ret = utils.get_script_result(sn,data)
    if ret:
        return ret

    run_slow = os.environ.get('run_slow')
    if run_slow is None:
        return

    ret = {}
    ret['return'] = False
    ret['solution'] = 'Not match'

    dockerid = utils.get_input_str("请输入不能删除文件所在的异常的容器ID,回车则跳过该脚本检查,如a335b68901cd:")
    if len(dockerid)<=0:
        utils.cache_script_result(sn,data,ret)
        print( __name__,':',ret)
        return ret

    try:
        inspectinfo = collect_data.get_docker_inspectinfo(sn, data, dockerid)
        if len(inspectinfo) <= 0:
            dockerid = utils.get_input_str("请输入正确的容器ID,如a335b68901cd:")
            inspectinfo = collect_data.get_docker_inspectinfo(sn, data, dockerid)
        if len(inspectinfo) <= 0:
            print( __name__,':invalid docker id and exit!')
        else:
            inspectinfo = inspectinfo.splitlines()
            for line in inspectinfo:
                if line.find('"WorkDir":') >= 0:
                    workdir = line.split(':')[1].strip()[1:-1]
                    if not os.path.exists(workdir):
                        ret['return'] = True
                        ret['solution'] = utils.format_result(cause='the WorkDir(%s) of docker(%s) has been deleted by mistake!'%(workdir,dockerid))
    except Exception as e:
        print( __name__,e)
        pass

    utils.cache_script_result(sn,data,ret)
    print( __name__,':',ret)
    return ret

def main():
    sn = ''
    data = {}
    os.environ['run_slow']="1"
    ret = query(sn, data)
    if ret['return']:
        result = {os.path.basename(__file__)[:-3]:ret['solution']}
        utils.post_ossre_diag(json.dumps(result,ensure_ascii=False))

if __name__ == "__main__":
    main()
