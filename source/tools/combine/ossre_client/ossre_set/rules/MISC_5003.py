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
    return '[systemd]systemd-logind cpu100%'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['systemd','systemd-logind cpu100%']

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

    # Check systemd-logind 100% cpu
    try:
        logind = collect_data.get_top_info(sn, data, 1)
        if len(logind) > 0:
            pos = int(-1)
            logind = logind.splitlines()
            for line in logind:
                if line.find('%CPU') >= 0:
                    line = line.strip().split()
                    count = 0
                    for item in line:
                        if item == '%CPU':
                            pos = count
                            break
                        count += 1
                    continue
                if line.find('systemd-logind') >= 0 and pos != -1:
                    line = line.strip().split()
                    if float(line[pos]) < float(90):
                        raise Exception("Not matched")
                    break
        else:
            raise Exception("Not matched")
        sessions = collect_data.get_cmddata(sn, data, "ls /run/systemd/sessions/ | wc -l")
        abandons = collect_data.get_cmddata(sn, data, "systemctl |grep 'of user' |grep 'abandoned'")
        sessions = int(sessions)
        abandons = int(abandons)
        if sessions > 100 and abandons > 100:
            ret['return'] = True
            ret['solution'] = utils.format_result(desc=("systemd-logind has high CPU usage"),
                    solution=("please check https://github.com/systemd/systemd/issues/1961 for solution!"))
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
