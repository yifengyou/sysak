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
    return "critical"

# Return one line to indentify this issue, this description will be
# displayed as a title for user to match the issue.
# Like "3.10: io hang in nvme盘"
def get_description():
    return '[NET]删除veth网卡卡住，导致容器发布失败'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return (['unregister_netdevice: waiting for vethxxx to become free. Usage count = 1','容器启动时 runc_init 进程D状态，卡在创建net ns流程',
		'删除网卡卡住','神龙机器eni bdf unbind卡住','容器发布失败'])

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

# Return whether this script need high CPU resource, like use search in crash
def need_high_res():
    return True

# Return whether need crash to attach /proc/kcore
def need_attach_crash():
    return True

# Return whether has a fast mode to run, if True, this script
# can be included in fast mode by process_engine.py.
def has_fast_mode():
    return True

# Reference: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=ee60ad219f5c7c4fb2f047f88037770063ef785f
def query(sn, data):
    ret = utils.get_script_result(sn,data)
    if ret:
        return ret

    run_all = os.environ.get('run_all')
    if run_all is None or int(run_all) != 1:
        return

    ret = {}
    ret['return'] = False
    ret['solution'] = 'Not match'
    hotfix = ''

    crash_inst = collect_data.get_live_crash(sn, data)
    bta = crash_inst.cmd('foreach bt')
    pidbts = crash.filter_all_bt_by_func(bta, 'netdev_run_todo')

    if len(pidbts) <= 0:
        utils.cache_script_result(sn,data,ret)
        print( __name__,':',ret)
        return ret

    pid = pidbts.keys()[0]
    stack = crash_inst.cmd('bt -f %s'%(pid))
    if 'PID:' in stack:
        stack = stack.splitlines()
        reach_sleep = 0
        dev = None
        for line in stack:
            if reach_sleep == 1:
                dev = line.strip().split()[1]
                break
            if 'msleep' in line:
                reach_sleep = 1
        if crash.valid_kernel_ptr('0x%s'%(dev)):
            search_k = crash_inst.cmd('search -k %s'%(dev))
            if len(search_k) > 0:
                search_k = search_k.splitlines()
                for addr in search_k:
                    if dev in addr and crash.valid_kernel_ptr('0x%s'%(addr.strip().split(':')[0])):
                        addr = addr.strip().split(':')[0]
                        kmeminfo = crash_inst.cmd('kmem -s %s'%(addr))
                        if len(kmeminfo) > 0 and kmeminfo.find('[ALLOCATED]') >= 0:
                            dst = kmeminfo.splitlines()[-1].strip()
                            if dst.startswith('[') and crash.valid_kernel_ptr('0x%s'%(dst[1:-1])):
                                dst = dst[1:-1]
                                dst_dev = crash_inst.cmd('struct dst_entry.dev %s'%(dst))
                                if dev not in dst_dev:
                                    continue
                                dst_struct = crash_inst.cmd('struct dst_entry %s'%(dst))
                                if len(dst_struct) > 0 and 'dst_ops' in dst_struct:
                                    matched = 0
                                    dst_struct = dst_struct.splitlines()
                                    expires = int(0)
                                    flags = ''
                                    for line in dst_struct:
                                        line = line.strip()
                                        if line.startswith('ops = ') and 'dst_ops' in line:
                                            matched = 1
                                            continue
                                        if line.startswith('expires = '):
                                            expires = int(line.split('=')[1].strip()[:-1])
                                            continue
                                        if line.startswith('flags = '):
                                            flags = line.split('=')[1].strip()[:-1]
                                            continue
                                    if matched == 0:
                                        continue
                                    if len(flags) <= 0:
                                        continue
                                    flags = int(flags)
                                    if (flags & 0x0010):
                                        continue
                                    jiffies = crash_inst.cmd('p jiffies').strip().split()[-1]
                                    if expires < int(jiffies):
                                        print( 'dst=%s leakage which cause that net_device(%s) cannot be unregistered'%(dst,dev))
                                        ret['return'] = True
                                        ret['solution'] = utils.format_result(desc=("unregister veth device hang"),
                                            commitid=("https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=ee60ad219f5c7c4fb2f047f88037770063ef785f"))
                                        break

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
