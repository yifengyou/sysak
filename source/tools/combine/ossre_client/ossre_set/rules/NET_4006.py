# -*- coding: utf-8 -*-
# @Author: tuquan

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

#Reference: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=ca11b798998a62c2bf87ea0477b5c60af25ba46d

# Return one line to indentify this issue
def get_description():
    return "[NET]mlx:alloc page failure"

# Return some keywords of this issue
def get_issue_keywords():
    return ["page allocation failure", "__kmalloc_large_node", "__kmalloc_node", "mlx5e_allo_rq"]

# Return some input hints of this issue
def get_input_hints():
    return

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
    if (dmesg.find('ifup-eth: page allocation failure') >= 0 and dmesg.find('kmalloc_large_node+0x') >= 0 and
            dmesg.find('mlx5e_alloc_rq+0x') >= 0 ):
        ret['return'] = True
        ret['solution'] = utils.format_result(desc=("ifup-eth: page allocation failure: order:6, mode:0x30c0d0"),
            commitid=("https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=ca11b798998a62c2bf87ea0477b5c60af25ba46d"))

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
