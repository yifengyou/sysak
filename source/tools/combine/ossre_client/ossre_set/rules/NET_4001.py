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
# default is 'warning'
def get_severe_level():
    return 'error'

# Return one line to indentify this issue, this description will be
# displayed as a title for user to match the issue.
# Like "3.10: io hang in nvme盘"
def get_description():
    return '[NET]netns泄漏导致内存不足'

# Return some keywords of this issue, these keywords will be queried based on user's input
# Like ["IO hang", "nvme", "3.10", "io util 100%", "hung task", "大量D任务", "load高"]
def get_issue_keywords():
    return ['netns泄漏','内存泄漏','page allocation failure: order:']

# Return some input hints of this issue
# Like ["hung task", "io util 100%", "大量D任务", "load高","IO hang"]
def get_input_hints():
    return ''

# Return some categories of this issue, these categories will be used by ossre.
# Available categories: ['HIGHSYS','HIGHLOAD','HANG','MEMLEAK','DEADLOCK','SOFTLOCKUP','CONFIG'
# 'HUNGTASK','RCUSTALL','DATA_CORRUPTION','RESOURCE_LEAK','REFERENCE_LEAK','NET_DROP'...]
def get_category():
    return ['MEMLEAK','HANG']

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

#Reference: https://lkml.org/lkml/2019/5/1/51
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

    cmd = "lsmod | grep auth_rpcgss"
    mod = collect_data.get_cmddata(sn, data, cmd, 1).strip()
    if len(mod) <= 0:
        utils.cache_script_result(sn,data,ret)
        print( __name__,':',ret)
        return ret
    
    crash_inst = collect_data.get_live_crash(sn, data)
    list_addr = ''
    net_namespace_list = crash_inst.cmd('p net_namespace_list').strip()
    if len(net_namespace_list) > 0:
        net_namespace_list = net_namespace_list.strip().splitlines()
        for line in net_namespace_list:
            line = line.strip()
            if line.find('next = 0xffff') >= 0:
                list_addr = line.split()[2]
    offset = 0
    if len(list_addr) > 0 and crash.valid_kernel_ptr(list_addr):
        net_off = crash_inst.cmd('struct net.list -xo').strip()
        if len(net_off) > 0:
            net_off = net_off.splitlines()
            for line in net_off:
                if 'list' in line:
                    line = line.strip()
                    net_off = line[line.find('[')+1:line.find(']')]
                    offset = int(net_off,16)
    netns_list = int(list_addr,16)
    if netns_list > 0:
        netns_list = hex(netns_list-offset)[:-1]
        count = 0
        need_cont = True
        while need_cont:
            netns = crash_inst.cmd('struct net.count,list %s'%(netns_list)).strip()
            if len(netns) > 0:
                if 'counter = 2' in netns:
                    search_str = 'search -k %s'%(netns_list)
                    search_k = crash_inst.cmd(search_str).strip()
                    if len(search_k) > 0:
                        search_k = search_k.splitlines()
                        for addr in search_k:
                            addr = addr.strip().split(':')[0]
                            if addr.endswith('060') or addr.endswith('d60'):
                                kmem_s = crash_inst.cmd('kmem -s %s'%(addr)).strip()
                                if 'kmalloc-2048' in kmem_s:
                                    kmem_s = kmem_s.strip().splitlines()[-1].strip()
                                    if kmem_s.find('[') >= 0:
                                        xprt_addr = '0x%s'%(kmem_s[kmem_s.find('[')+1:kmem_s.find(']')])
                                        xprt = crash_inst.cmd('struct rpc_xprt %s'%(xprt_addr)).strip()
                                        if len(xprt) > 0 and 'gssproxy.sock' in xprt and 'xprt_net = %s'%(netns_list) in xprt:
                                            num_netns = crash_inst.cmd('list net.list -h %s | wc -l'%(netns_list)).strip()
                                            ret['return'] = True
                                            ret['solution'] = utils.format_result(desc=("netns泄漏导致内存不足"),
                                                commitid=("https://lkml.org/lkml/2019/5/1/51"))
                                            utils.cache_script_result(sn,data,ret)
                                            print( __name__,':',ret)
                                            return ret
                if 'next = 0xffff' in netns:
                    netns = netns.splitlines()
                    for line in netns:
                        if 'next = 0xffff' in line and list_addr not in line:
                            line = line.strip().split()[2].strip()
                            if line.endswith(','):
                                line = line[:-1]
                            netns_list = int(line,16)
                            netns_list = hex(netns_list-offset)[:-1]
                            break
                        if list_addr in line:
                            need_cont = False
                else:
                    print( 'invalid ',netns)
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
