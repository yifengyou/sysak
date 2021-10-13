# -*- coding: utf-8 -*-
# @Author: lichen/shiyan/tuquan

"""
This script is the entry of ossre. It tries to detect OS exceptions and diagnose these
exceptions.

"""

import os
import sys
import datetime,time
if sys.version[0] == '2':
    import httplib
elif sys.version[0] == '3':
    import http.client as httplib
import subprocess
import re
import socket
import json
import argparse
import traceback
import importlib

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/tools/"%(os.path.dirname(os.path.abspath(__file__))))
sys.path.append("%s/vmcore"%(os.path.dirname(os.path.abspath(__file__))))
sys.path.append("%s/rules"%(os.path.dirname(os.path.abspath(__file__))))

import cgroupcheck
import memleak_diag
import collect_data
import utils
import hwcheck
import logcheck
import cust_const

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

VMCORE_FUNCS = ['parse_panic']
DMESG_FUNCS = []
#LOGDIAG_FUNC = 'log_diag'
CONFIG_FILE='ossre.conf'

run_offline = 0
run_all = 0
run_diag = 0
run_issuecheck = 0
run_logcheck = 0
run_panic = 0
run_verbose = 0
log_file=""
cache_data = {}

ossre_config= {
        'highsys_thresh':30.0,
        'highio_thresh':30.0,
        'highsoftirq_thresh':30.0,
        'unreclaim_slab_thresh':20000000,
        'dentry_num':100000000,
        'memory_frag_thresh':20,
        'direct_reclaim_num':10000,
        'free_percent_thresh':5,
        'high_await_thresh':100.0,
        'net_retrans_thresh':30.0,
        'max_cgroup_num':1000
}
class Logger(object):
    def __init__(self, filename="/var/log/sysak/ossre.log"):
        if not os.path.exists("/var/log/sysak"):
            os.mkdir("/var/log/sysak",0755);
        self.log = open(filename, "w+")

    def write(self, message):
        self.log.write(message)
        self.log.flush()

    def flush(self):
        pass

print_logger = None

def get_logger():
    global print_logger
    if not print_logger:
        print_logger = Logger()
    return print_logger

logger = get_logger()

def get_tsar_path(cache_data):
    tsar_path = utils.get_tsar_path(cache_data)
    if len(tsar_path) <= 0:
        print("Warning: Please install ssar or tsar!")

    return tsar_path

def do_cmd(cmd):
    output = os.popen(cmd)
    ret = output.read().strip()
    output.close()
    return ret

def get_dmesg(data):
    if 'dmesg' not in data:
        try:
            cmd = 'dmesg 2>/dev/null'
            data['dmesg'] = do_cmd(cmd)
        except:
            print( 'get_dmesg exception!')
            data['dmesg'] = ''
    return data['dmesg']

def get_syslog(data):
    if 'syslog' not in data:
        try:
            cmd = 'grep "kernel:" /var/log/messages | tail -n 3000 2>/dev/null'
            data['syslog'] = do_cmd(cmd)
        except:
            print( 'get_syslog exception!')
            data['syslog'] = ''
    return data['syslog']
def get_fs_value(data, fs_path, updated=0):
    if 'fs' not in data:
        data['fs'] = {}
    if updated or fs_path not in data['fs']:
        try:
            cmd = 'cat %s 2>/dev/null'%fs_path
            data['fs'][fs_path] = do_cmd(cmd)
        except:
            print( 'get_fs_value(path %s) exception!'%fs_path)
            data['fs'][proc_path] = ''

    return data['fs'][fs_path]

def get_meminfo(data, updated=0):
    if updated or 'meminfo' not in data:
        data['meminfo'] = ''
        try:
            cmd = 'cat /proc/meminfo 2>/dev/null'
            data['meminfo'] = do_cmd(cmd)
        except:
            print( 'get_meminfo exception!')
            data['meminfo'] = ''
    return data['meminfo']

def get_freeinfo(data, updated=0):
    if updated or 'freeinfo' not in data:
        try:
            cmd = 'free -m 2>/dev/null'
            data['freeinfo'] = do_cmd(cmd)
        except:
            print( 'get_freeinfo exception!')
            data['freeinfo'] = ''
    return data['freeinfo']

def get_tsar_data(data, cmd):
    if 'tsar' not in data:
        data['tsar'] = {}
    if cmd not in data['tsar']:
        data['tsar'][cmd] = ''
        try:
            data['tsar'][cmd] = do_cmd(cmd)
        except:
            print( 'get_tsar_data(cmd %s) exception!'%cmd)
            data['tsar'][cmd] = ''
    return data['tsar'][cmd]

def get_kernel_version(data):
    if 'version' not in data:
        data['version'] = ''
        try:
            cmd = 'cat /proc/version 2>/dev/null'
            data['version'] = do_cmd(cmd)
        except:
            print( 'get_osversion_info exception!')
            data['version'] = ''
    return data['version']

def get_cmddata(data, cmd, updated=0):
    if updated or cmd not in data:
        data[cmd] = ''
        try:
            data[cmd] = do_cmd(cmd)
        except:
            print( 'get_cmddata exception!')
            data[cmd] = ''
    return data[cmd]


DEFAULT_SOLUTION = "请联系操作系统专家进行相关系统状态分析。"
#status {"normal", "warning", "critical", "fatal"}
def check_log(result,log_file):
    try:
        log_ret = logcheck.query("", cache_data, log_file)
        if run_panic != 1:
            result['fields']['LOG']['detail'] = log_ret['solution']
            result['fields']['LOG']['summary'] += log_ret['solution']['summary']
            result['fields']['cust']['LOG'] = log_ret['solution']['cust']
        else:
            result['fields']['SLI']['CRASH'] = {}
            result['fields']['SLI']['CRASH']['detail'] = log_ret['solution']['panic']['solution']
    except Exception as e:
        print( 'check_log: exception(%s)!'%(e))
        traceback.print_exc()
        pass

def post_ossre_diag(diagdata):
    return

# recommended hotfixes for each version
# critical and important hotfixes, like panic, oom and load ...
hotfix_table = {
    }

def get_need_hotfix():
    cmd = 'uname -r 2>/dev/null'
    version = get_cmddata(cache_data,cmd)
    if len(hotfix_table.get(version, [])) > 0:
        return hotfix_table.get(version)

    return []

def get_crash_path():
    try:
        if os.path.exists('/etc/kdump.conf'):
            with open('/etc/kdump.conf', 'r') as f1:
                lines = f1.readlines()
                part = ''
                var_path = ''
                for line in lines:
                    if line.startswith('ext4'):
                        part0 = line.split()[1]
                        if part0.startswith('/dev/'):
                            cmd = 'lsblk %s'%(part0)
                            part = get_cmddata(cache_data,cmd).splitlines()[-1].split()[-1]
                        elif part0.startswith('LABEL='):
                            part = part0.split('=')[-1]
                    elif line.startswith('path'):
                        var_path = line.split()[-1]
            if len(part) > 0 and len(var_path) > 0:
                return "%s%s"%(part,var_path)
            elif len(var_path) > 0:
                return var_path
        else:
            return '/var/crash/'
    except:
        pass
        return '/var/crash/'


def check_crash(ret):
    total_crash_num = 0
    ret['fields']['SLI']['CRASH'] = {}
    ret['fields']['SLI']['CRASH']['local'] = {}
    ret['fields']['SLI']['CRASH']['local']['total_num'] = 0
    ret['fields']['SLI']['CRASH']['local']['detail'] = []
    ret['fields']['SLI']["summary"] += "1)宕机:\n"
    total_crash_num = 0
    # Check local crash dirs
    crash_path = get_crash_path()
    try:
        crash_time = ""
        for subdir, dirs, files in os.walk(crash_path):
            for file in files:
                filepath = subdir + os.sep + file
                if os.path.isfile(filepath) and filepath.endswith('-dmesg.txt'):
                    total_crash_num += 1
                    crash_one = {"vmcore链接":subdir}
                    ret['fields']['SLI']['CRASH']['local']['detail'].append(crash_one)
                    tmp = subdir[subdir.rfind(".")+1:]
                    crash_time += tmp[tmp.find("-")+1:]
                    crash_time += "\t"
        if total_crash_num > 0:
            ret['status'] = -1
            ret['fields']['SLI']['CRASH']['local']['total_num'] = total_crash_num
            ret['fields']['SLI']["summary"] += "本地机器上检查到宕机%s次,宕机时间:%s\n"%(total_crash_num,crash_time)

            ret['fields']['cust']['SLI']['CRASH'] = {}
            ret['fields']['cust']['SLI']['CRASH']['category'] = cust_const.CRASH['category']
            ret['fields']['cust']['SLI']['CRASH']['level'] = cust_const.CRASH['level']
            ret['fields']['cust']['SLI']['CRASH']['name'] = cust_const.CRASH['name']
            ret['fields']['cust']['SLI']['CRASH']['desc'] = cust_const.CRASH['desc']
            ret['fields']['cust']['SLI']['CRASH']['solution'] = cust_const.CRASH['solution']
            ret['fields']['cust']['SLI']['CRASH']['params'] = {}
            ret['fields']['cust']['SLI']['CRASH']['params']['total_crash_num'] = total_crash_num
            ret['fields']['cust']['SLI']['CRASH']['params']['crash_time'] = crash_time
            ret['fields']['cust']['SLI']['CRASH']['summary'] = cust_const.CRASH['summary_format']%(
                ret['fields']['cust']['SLI']['CRASH']['params']['total_crash_num'],ret['fields']['cust']['SLI']['CRASH']['params']['crash_time'])

            if run_diag == 1:
                data = {}
                for func in VMCORE_FUNCS:
                    mod = importlib.import_module(func)
                    crash_ret = mod.query("", cache_data)
                    ret['fields']['SLI']['CRASH']['local']['detail'] = crash_ret['solution']
                    ret['fields']['SLI']["summary"] += "诊断原因:\n%s\n"%(json.dumps(crash_ret['solution'],ensure_ascii=False))
                    ret['fields']['cust']['SLI']['CRASH']['summary'] += ("诊断原因:\n%s\n"%(
                        json.dumps(crash_ret['solution'],ensure_ascii=False)))
        else:
            ret['fields']['SLI']["summary"] += "None\n"
    except Exception as e:
        print( 'check local crash exception:',e)
        traceback.print_exc()

def check_cpu_indicator(ret):
    try:
        summary = ""
        ret['fields']['SLI']['SCHED']['detail'] = {}
        ret['fields']['SLI']['SCHED']['detail']['highsys'] = {}
        ret['fields']['SLI']['SCHED']['detail']['highload'] = {}
        ret['fields']['SLI']['SCHED']['detail']['highio'] = {}
        ret['fields']['SLI']['SCHED']['detail']['highsoftirq'] = {}
        ret['fields']['SLI']['SCHED']['highsys_num'] = {}
        ret['fields']['SLI']['SCHED']['highsys_num']['status'] = "normal"
        ret['fields']['SLI']['SCHED']['highio_num'] = {}
        ret['fields']['SLI']['SCHED']['highio_num']['status'] = "normal"
        ret['fields']['SLI']['SCHED']['highsoftirq_num'] = {}
        ret['fields']['SLI']['SCHED']['highsoftirq_num']['status'] = "normal"
        ret['fields']['SLI']['SCHED']['highload_num'] = {}
        ret['fields']['SLI']['SCHED']['highload_num']['status'] = "normal"
        ret['fields']['SLI']['summary'] += "2)CPU相关:\n"
        tsar_path = get_tsar_path(cache_data)
        if len(tsar_path) > 0:
            cmd = ('%s --cpu -i 1 -n 1'%(tsar_path))
            tsar = get_tsar_data(cache_data,cmd).splitlines()
            sys_num = 0
            io_num = 0
            softirq_num = 0
            index = 2
            sys_sum = ""
    
            for line in tsar:
                line = line.strip()
                if (line.startswith('Time') or len(line) == 0 or line.startswith('MAX') or
                    line.startswith('MEAN') or line.startswith('MIN')):
                    continue
                item = line.split()
                if len(item) == 7:
                    try:
                        sysutil = float(item[2])
                        ioutil = float(item[3])
                        softirqutil = float(item[5])
                        if (sysutil >= ossre_config['highsys_thresh'] or
                                ioutil >= ossre_config['highio_thresh'] or
                                softirqutil >= ossre_config['highsoftirq_thresh']):
                            sys_sum += "时间:%s "%(item[0])
                        if sysutil >= ossre_config['highsys_thresh']:
                            ret['fields']['SLI']['SCHED']['detail']['highsys'][item[0]] = sysutil
                            sys_num += 1
                            sys_sum += " sys:%s "%(sysutil)
                        ioutil = float(item[3])
                        if ioutil >= ossre_config['highio_thresh']:
                            ret['fields']['SLI']['SCHED']['detail']['highio'][item[0]] = ioutil
                            io_num += 1
                            sys_sum += " ioutil:%s "%(ioutil)
                        softirqutil = float(item[5])
                        if softirqutil >= ossre_config['highsoftirq_thresh']:
                            ret['fields']['SLI']['SCHED']['detail']['highsoftirq'][item[0]] = softirqutil
                            softirq_num += 1
                            sys_sum += " sirq:%s "%(softirqutil)
                        if (sysutil >= ossre_config['highsys_thresh'] or
                                ioutil >= ossre_config['highio_thresh'] or
                                softirqutil >= ossre_config['highsoftirq_thresh']):
                            sys_sum += "\n"
                    except:
                        #traceback.print_exc()
                        pass
            if sys_num > 1:
                ret['fields']['SLI']['SCHED']['highsys_num']['value'] = sys_num
                ret['fields']['SLI']['SCHED']['highsys_num']['status'] = "warning"
                ret['fields']['SLI']['SCHED']['highsys_num']['info'] = ("检查系统近一天的CPU sys占比，"
                    "如果存在大于%.2f%%的情况，就告警。"
                    "当前系统近一天sys占比超过%.2f%%的时间超过%s分钟"%(
                    ossre_config['highsys_thresh'],ossre_config['highsys_thresh'],sys_num))
                ret['fields']['SLI']['SCHED']['highsys_num']['solution'] = DEFAULT_SOLUTION
            if io_num > 1:
                ret['fields']['SLI']['SCHED']['highio_num']['value'] = io_num
                ret['fields']['SLI']['SCHED']['highio_num']['status'] = "warning"
                ret['fields']['SLI']['SCHED']['highio_num']['info'] = ("检查系统近一天的CPU iowait占比，"
                    "如果存在大于%.2f%%的情况，就告警。"
                    "当前系统近一天iowait占比超过%.2f%%的时间超过%s分钟"%(
                    ossre_config['highio_thresh'],ossre_config['highio_thresh'],io_num))
                ret['fields']['SLI']['SCHED']['highio_num']['solution'] = DEFAULT_SOLUTION
            if softirq_num > 1:
                ret['fields']['SLI']['SCHED']['highsoftirq_num'] = softirq_num
                ret['fields']['SLI']['SCHED']['highsoftirq_num']['status'] = "warning"
                ret['fields']['SLI']['SCHED']['highsoftirq_num']['info'] = ("检查系统近一天的CPU softirq占比，"
                    "如果存在大于%.2f%%的情况，就告警。"
                    "当前系统近一天softirq占比超过%.2f%%的时间超过%s分钟"%(
                    ossre_config['highsoftirq_thresh'],ossre_config['highsoftirq_thresh'],softirq_num))
                ret['fields']['SLI']['SCHED']['highsoftirq_num']['solution'] = DEFAULT_SOLUTION
    
            if len(sys_sum) > 0:
                summary += "CPU利用率高异常:\n%s"%(sys_sum)

                ret['fields']['cust']['SLI']['highsys'] = {}
                ret['fields']['cust']['SLI']['highsys']['category'] = cust_const.highsys['category']
                ret['fields']['cust']['SLI']['highsys']['level'] = cust_const.highsys['level']
                ret['fields']['cust']['SLI']['highsys']['desc'] = cust_const.highsys['desc']
                ret['fields']['cust']['SLI']['highsys']['name'] = cust_const.highsys['name']
                ret['fields']['cust']['SLI']['highsys']['solution'] = ""
                ret['fields']['cust']['SLI']['highsys']['params'] = {}
                ret['fields']['cust']['SLI']['highsys']['params']['sys_sum'] = sys_sum
                ret['fields']['cust']['SLI']['highsys']['summary'] = cust_const.highsys['summary_format']%(ret['fields']['cust']['SLI']['highsys']['params']['sys_sum'])


        loadcheck_mode = 1
        if run_diag == 1 and run_all == 1:
            loadcheck_mode = 2

        load_num = 0
        load_sum = ""
        load_ret = {}
        #loadcheck.loadcheck_entry(loadcheck_mode, load_ret)
        #load_num = load_ret['load_num']
        #load_sum += load_ret['summary']
        if load_num > 0:
            ret['fields']['SLI']['SCHED']['highload_num']['value'] = load_num
            ret['fields']['SLI']['SCHED']['highload_num']['status'] = "warning"
            ret['fields']['SLI']['SCHED']['highload_num']['info'] = ("检查系统近一天的系统load情况，"
                "如果存在load值异常的情况，就告警。"
                "当前系统近一天load值异常超过%s次"%(load_num))
            ret['fields']['SLI']['SCHED']['highload_num']['solution'] = DEFAULT_SOLUTION
            ret['status'] = -1
        if len(load_sum) > 0:
            summary += "Load高异常:\n%s"%(load_sum)

            ret['fields']['cust']['SLI']['highload'] = {}
            ret['fields']['cust']['SLI']['highload']['category'] = cust_const.highload['category']
            ret['fields']['cust']['SLI']['highload']['level'] = cust_const.highload['level']
            ret['fields']['cust']['SLI']['highload']['desc'] = cust_const.highload['desc']
            ret['fields']['cust']['SLI']['highload']['name'] = cust_const.highload['name']
            ret['fields']['cust']['SLI']['highload']['solution'] = cust_const.highload['solution']
            ret['fields']['cust']['SLI']['highload']['params'] = {}
            ret['fields']['cust']['SLI']['highload']['params']['load_num'] = load_num
            ret['fields']['cust']['SLI']['highload']['summary'] = cust_const.highload['summary_format']%(load_sum)

        if len(summary) <= 0:
            summary = "None\n"
        ret['fields']['SLI']['summary'] += summary
    except Exception as e:
        print( 'check_cpu_indicator exception:',e)
        traceback.print_exc()
        pass

def check_mem_indicator(ret):
    try:
        summary = ""
        ret['fields']['SLI']['MEM']['detail'] = {}
        ret['fields']['SLI']['summary'] += "3)内存相关:\n"
        vmstat = get_fs_value(cache_data,"/proc/vmstat").splitlines()
        """stall_lat = get_fs_value(cache_data, "/sys/fs/cgroup/memory/memory.direct_reclaim_latency")
        high_stall_lat = 0
        if len(stall_lat) > 0:
            stall_lat = stall_lat.splitlines()
            for line in stall_lat:
                line = line.strip()
                if line.startswith('10-100ms:') or line.startswith('>=100ms:'):
                    items = line.split()
                    high_stall_lat += int(items[1])
                    if len(items) == 3:
                        high_stall_lat += int(items[2])
        if high_stall_lat > 0:
            ret['fields']['SLI']['MEM']['high_directreclaim_latency'] = high_stall_lat
            ret['status'] = -1"""
        for line in vmstat:
            if line.find('allocstall_normal') >= 0:
                stall = int(line.split()[1])
                ret['fields']['SLI']['MEM']['directreclaim'] = stall
            elif line.find('allocstall ') >= 0:
                stall = int(line.split()[1])
                ret['fields']['SLI']['MEM']['directreclaim'] = stall
                if stall > 100:
                    ret['status'] = -1
            elif line.find('compact_stall ') >= 0:
                stall = int(line.split()[1])
                ret['fields']['SLI']['MEM']['compact_stall'] = stall
        if ('directreclaim' in ret['fields']['SLI']['MEM'] and
           ret['fields']['SLI']['MEM']['directreclaim'] > ossre_config['direct_reclaim_num']):
           summary += "主机存在频繁directreclaim达%s次\n"%(
               ret['fields']['SLI']['MEM']['directreclaim'])

        cgmstat = get_fs_value(cache_data,"/sys/fs/cgroup/memory/memory.stat").splitlines()
        for line in cgmstat:
            if 'total_allocstall' in line:
                stall = int(line.split()[1])
                ret['fields']['SLI']['MEM']['cg_directreclaim'] = stall
        if ('cg_directreclaim' in ret['fields']['SLI']['MEM'] and
            ret['fields']['SLI']['MEM']['cg_directreclaim'] > 10000):
            summary += "cgroup存在频繁directreclaim达%s次\n"%(
                    ret['fields']['SLI']['MEM']['cg_directreclaim'])

            ret['fields']['cust']['SLI']['directreclaim'] = {}
            ret['fields']['cust']['SLI']['directreclaim']['category'] = cust_const.directreclaim['category']
            ret['fields']['cust']['SLI']['directreclaim']['level'] = cust_const.directreclaim['level']
            ret['fields']['cust']['SLI']['directreclaim']['desc'] = cust_const.directreclaim['desc']
            ret['fields']['cust']['SLI']['directreclaim']['name'] = cust_const.directreclaim['name']
            ret['fields']['cust']['SLI']['directreclaim']['solution'] = cust_const.directreclaim['solution']
            ret['fields']['cust']['SLI']['directreclaim']['params'] = {}
            ret['fields']['cust']['SLI']['directreclaim']['params']['cg_directreclaim'] = ret['fields']['SLI']['MEM']['cg_directreclaim']
            ret['fields']['cust']['SLI']['directreclaim']['summary'] = (
                cust_const.directreclaim['summary_format']%(
                ret['fields']['cust']['SLI']['directreclaim']['params']['cg_directreclaim']))

            if run_diag == 1:
                tmp = cgroupcheck.directreclaim_check()
                summary += tmp
                ret['fields']['cust']['SLI']['directreclaim']['summary'] += tmp

        # check free mem
        # check slab total
        ret['fields']['SLI']['MEM']['free_percent'] = 0
        ret['fields']['SLI']['MEM']['unreclaimslab'] = {}
        ret['fields']['SLI']['MEM']['unreclaimslab']['status'] = "normal"
        total = 0
        avail = 0
        need_diag = 0
        meminfo = get_fs_value(cache_data, "/proc/meminfo").splitlines()
        for line in meminfo:
            if line.startswith("SUnreclaim:"):
                try:
                    slab = int(line.split()[1])
                    value = '%s kB'%(slab)
                    ret['fields']['SLI']['MEM']['unreclaimslab']['value'] = value
                    if slab > ossre_config['unreclaim_slab_thresh']:
                        ret['fields']['SLI']['MEM']['unreclaimslab']['status'] = "warning"
                        ret['fields']['SLI']['MEM']['unreclaimslab']['info'] = ("检查/proc/memory中的"
                            "unreclaimslab字段的值，如果大于%ld，就告警，"
                            "过高的不可回收的slab内存可能会导致系统异常，当前值为：%s" %(
                            ossre_config['unreclaim_slab_thresh'],value))
                        ret['fields']['SLI']['MEM']['unreclaimslab']['solution'] = DEFAULT_SOLUTION
                        summary += "存在过高不可回收Slab内存达%skB\n"%(slab)

                        ret['fields']['cust']['SLI']['unreclaimslab'] = {}
                        ret['fields']['cust']['SLI']['unreclaimslab']['category'] = cust_const.unreclaimslab['category']
                        ret['fields']['cust']['SLI']['unreclaimslab']['level'] = cust_const.unreclaimslab['level']
                        ret['fields']['cust']['SLI']['unreclaimslab']['desc'] = cust_const.unreclaimslab['desc']
                        ret['fields']['cust']['SLI']['unreclaimslab']['name'] = cust_const.unreclaimslab['name']
                        ret['fields']['cust']['SLI']['unreclaimslab']['solution'] = cust_const.unreclaimslab['solution']
                        ret['fields']['cust']['SLI']['unreclaimslab']['params'] = {}
                        ret['fields']['cust']['SLI']['unreclaimslab']['params']['unreclaimslab_num'] = slab
                        ret['fields']['cust']['SLI']['unreclaimslab']['summary'] = (
                            cust_const.unreclaimslab['summary_format']%(ret['fields']['cust']['SLI']['unreclaimslab']['params']['unreclaimslab_num']))

                        need_diag = 1
                except:
                    traceback.print_exc()
                    pass
            elif line.startswith("MemTotal:"):
                total = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                avail = int(line.split()[1])
                ret['fields']['SLI']['MEM']['free_percent'] = avail*100/total
                if ret['fields']['SLI']['MEM']['free_percent'] < ossre_config['free_percent_thresh']:
                    summary += ("free内存不足,仅占总内存%s%%,容易引起sys飙高和频繁OOM,甚至ssh失联\n"%(
                        str(ret['fields']['SLI']['MEM']['free_percent'])))

                    ret['fields']['cust']['SLI']['lowfree'] = {}
                    ret['fields']['cust']['SLI']['lowfree']['category'] = cust_const.lowfree['category']
                    ret['fields']['cust']['SLI']['lowfree']['level'] = cust_const.lowfree['level']
                    ret['fields']['cust']['SLI']['lowfree']['desc'] = cust_const.lowfree['desc']
                    ret['fields']['cust']['SLI']['lowfree']['name'] = cust_const.lowfree['name']
                    ret['fields']['cust']['SLI']['lowfree']['solution'] = cust_const.lowfree['solution']
                    ret['fields']['cust']['SLI']['lowfree']['params'] = {}
                    ret['fields']['cust']['SLI']['lowfree']['params']['free_percent'] = str(ret['fields']['SLI']['MEM']['free_percent'])
                    ret['fields']['cust']['SLI']['lowfree']['summary'] = (
                        cust_const.lowfree['summary_format']%(ret['fields']['cust']['SLI']['lowfree']['params']['free_percent']))

                    need_diag = 1
        if need_diag == 1 and run_diag == 1:
            memleak_ret = memleak_diag.query("", cache_data)
            ret['fields']['SLI']['MEM']['diag'] = memleak_ret['solution']
            summary += "诊断slab和内存泄漏: %s\n"%(memleak_ret['solution']['summary'])
            if memleak_ret['return']:

                ret['fields']['cust']['SLI']['memleak'] = {}
                ret['fields']['cust']['SLI']['memleak']['category'] = cust_const.memleak['category']
                ret['fields']['cust']['SLI']['memleak']['level'] = cust_const.memleak['level']
                ret['fields']['cust']['SLI']['memleak']['desc'] = cust_const.memleak['desc']
                ret['fields']['cust']['SLI']['memleak']['name'] = cust_const.memleak['name']
                ret['fields']['cust']['SLI']['memleak']['solution'] = cust_const.memleak['solution']
                ret['fields']['cust']['SLI']['memleak']['summary'] = (
                    cust_const.memleak['summary_format']%(memleak_ret['solution']['summary']))
 
        dentry_num = get_fs_value(cache_data, "/sys/kernel/slab/dentry/objects").strip().split()[0]
        dentry_num = int(dentry_num)
        ret['fields']['SLI']['MEM']['dentry_num'] = {}
        ret['fields']['SLI']['MEM']['dentry_num']['value'] = dentry_num
        ret['fields']['SLI']['MEM']['dentry_num']['status'] = "normal"
        if dentry_num >= ossre_config['dentry_num']:
            ret['fields']['SLI']['MEM']['dentry_num']['status'] = "warning"
            ret['fields']['SLI']['MEM']['dentry_num']['info'] = ("检查系统的dentry数量，"
                "dentry数量过大（经验值：超过%dM）会导致内核在遍历dentry耗时长sys飙高,当前数量:%s"%((
                ossre_config['dentry_num']/1000000),str(dentry_num)))
            ret['fields']['SLI']['MEM']['dentry_num']['solution'] = "请释放一下cache，或者"+DEFAULT_SOLUTION
            summary += "dentry数量过大,当前数量:%s,存在遍历dentry耗时长导致sys飙高风险\n"%(dentry_num)

            ret['fields']['cust']['SLI']['highdentry'] = {}
            ret['fields']['cust']['SLI']['highdentry']['category'] = cust_const.highdentry['category']
            ret['fields']['cust']['SLI']['highdentry']['level'] = cust_const.highdentry['level']
            ret['fields']['cust']['SLI']['highdentry']['desc'] = cust_const.highdentry['desc']
            ret['fields']['cust']['SLI']['highdentry']['name'] = cust_const.highdentry['name']
            ret['fields']['cust']['SLI']['highdentry']['solution'] = cust_const.highdentry['solution']
            ret['fields']['cust']['SLI']['highdentry']['params'] = {}
            ret['fields']['cust']['SLI']['highdentry']['params']['dentry_num'] = dentry_num
            ret['fields']['cust']['SLI']['highdentry']['summary'] = (
                cust_const.highdentry['summary_format']%(ret['fields']['cust']['SLI']['highdentry']['params']['dentry_num']))

        cmd = " cat /proc/buddyinfo | grep 'Normal' "
        buddyinfo = get_cmddata(cache_data,cmd).strip()
        ret['fields']['SLI']['MEM']['memory_frag'] = {}
        ret['fields']['SLI']['MEM']['memory_frag']['value'] = buddyinfo
        ret['fields']['SLI']['MEM']['memory_frag']['status'] = "normal"

        cmd = " cat /proc/buddyinfo | grep 'Normal' |awk '{if ($10 + $11 + $12 + $13 + $14 + $15 < 20 ) print $0}' | wc -l "
        frag = get_cmddata(cache_data,cmd).strip()
        if int(frag) > 0:
            ret['fields']['SLI']['MEM']['memory_frag']['status'] = "warning"
            ret['fields']['SLI']['MEM']['memory_frag']['info'] = ("检查系统的/proc/buddy_info接口，"
                "统计高阶内存的情况，如果高阶内存很少，可能会导致申请高阶内存失败或者由于内存页频繁合并导致系统sys高，"
                "load高，当前buddy_info情况：\n"+buddyinfo)
            ret['fields']['SLI']['MEM']['memory_frag']['solution'] = ("请释放一下cache，"
                "或者调整一下min_free_kbytes的值，或者"+DEFAULT_SOLUTION)
            summary += ("高阶内存不足,存在内存碎片问题,可能会导致申请高阶内存失败"
                "或者由于内存页频繁合并导致系统sys高,load高\n")

            ret['fields']['cust']['SLI']['memfrag'] = {}
            ret['fields']['cust']['SLI']['memfrag']['category'] = cust_const.memfrag['category']
            ret['fields']['cust']['SLI']['memfrag']['level'] = cust_const.memfrag['level']
            ret['fields']['cust']['SLI']['memfrag']['desc'] = cust_const.memfrag['desc']
            ret['fields']['cust']['SLI']['memfrag']['name'] = cust_const.memfrag['name']
            ret['fields']['cust']['SLI']['memfrag']['solution'] = cust_const.memfrag['solution']
            ret['fields']['cust']['SLI']['memfrag']['summary'] = cust_const.memfrag['summary_format']

        if len(summary) <= 0:
            summary = "None\n"
        ret['fields']['SLI']['summary'] += summary
    except Exception as e:
        print( 'check_mem_indicator exception:',e)
        traceback.print_exc()
        pass

def get_watched_disks(blks, disks):
    if len(blks) > 0:
        blks = blks.splitlines()
        disk = ""
        home_disk = ""
        root_disk = ""
        for line in blks:
            line = line.strip()
            if line.endswith('disk'):
                disk = line.split()[0]
            elif line.endswith("/home"):
                home_disk = disk
            elif line.endswith("/"):
                root_disk = disk
        if len(home_disk) > 0:
            disks['home'] = home_disk
        elif len(root_disk) > 0 and root_disk != home_disk:
            disks['root'] = root_disk

def check_io_indicator(ret):
    try:
        summary = ""
        ret['fields']['SLI']['IO']['detail'] = {}
        ret['fields']['SLI']['summary'] += "4)IO相关:\n"
        cmd = ('lsblk 2>/dev/null')
        blks = get_cmddata(cache_data, cmd)
        await_index = 0
        qusize_index = 0
        need_diag = 0
        disks = {}
        get_watched_disks(blks, disks)
        if len(blks) > 0:
            blks = blks.splitlines()
            for line in blks:
                line = line.strip()
                blk = line.split()[0].strip()
                if (line.endswith('disk') and
                        (('home' in disks and blk == disks['home']) or
                        ('root' in disks and blk == disks['root']) or
                        (blk.find('nvme') >= 0))):
                    try:
                        tsar_path = get_tsar_path(cache_data)
                        if len(tsar_path) > 0:
                            cmd = ('%s --io -I %s -i 1 -n 1 2>/dev/null'%(tsar_path,blk))
                            io_stats = get_tsar_data(cache_data, cmd)
                            io_stats = io_stats.splitlines()
                            total_await = float(0.0)
                            total_num = 0
                            mean_await = float(0.0)
                            highawait_num = 0
                            io_sum = ""
                            for line in io_stats:
                               line = line.strip()
                               if len(line) <= 0:
                                   continue
                               if line.find('await') > 0 and await_index == 0:
                                    line = line.split()
                                    i = 0
                                    for item in line:
                                        if item.strip() == 'await':
                                            await_index = i
                                        elif item.strip() == 'qusize':
                                            qusize_index = i
                                        i += 1
                                    if await_index > 0:
                                        break
    
                            for line in io_stats:
                               line = line.strip()
                               if len(line) <= 0:
                                   continue
                               if (line.startswith('Time') or line.startswith('MAX') or
                                   line.startswith('MEAN') or line.startswith('MIN')) or "-----" in line:
                                   continue
                               else:
                                   try:
                                       line = line.split()
                                       await = float(line[await_index])
                                       qusize = float(line[qusize_index])
                                       if (await > ossre_config['high_await_thresh'] or qusize > 10):
                                           highawait_num += 1
                                           if highawait_num<10:
                                               io_sum += "时间:%s,await:%sms,qusize:%d\n"%(line[0],await,qusize)
                                   except:
                                       traceback.print_exc()
                                       pass
                            if ret['fields']['SLI']['IO'].get('highawait') is None:
                                ret['fields']['SLI']['IO']['highawait'] = {}
                            ret['fields']['SLI']['IO']['highawait'][blk] = highawait_num
                            ret['status'] = -1
                            if len(io_sum) > 0:
                                summary += "%s盘存在高await:\n%s"%(blk,io_sum)

                    except:
                        #traceback.print_exc()
                        pass
        if len(summary) <= 0:
            summary = "None\n"
        else:

            ret['fields']['cust']['SLI']['highiowait'] = {}
            ret['fields']['cust']['SLI']['highiowait']['category'] = "IO"
            ret['fields']['cust']['SLI']['highiowait']['level'] = "warning"
            ret['fields']['cust']['SLI']['highiowait']['desc'] = ("检查一天内iowait高时间点,"
                "高iowait容易导致说明IO压力大或者存储盘故障,容易影响应用QPS和RT")
            ret['fields']['cust']['SLI']['highiowait']['name'] = "iowait高检查"
            ret['fields']['cust']['SLI']['highiowait']['solution'] = ""
            ret['fields']['cust']['SLI']['highiowait']['params'] = {}
            ret['fields']['cust']['SLI']['highiowait']['params']['highawait_num'] = highawait_num
            ret['fields']['cust']['SLI']['highiowait']['summary'] = summary

        ret['fields']['SLI']['summary'] += summary

    except Exception as e:
        print( 'check_io_indicator exception:',e)
        traceback.print_exc()
        pass

def check_net_indicator(ret):
    try:
        summary = ""
        ret['fields']['SLI']['NET']['highretran_num'] = {}
        ret['fields']['SLI']['NET']['highretran_num']['status'] = "normal"
        ret['fields']['SLI']['summary'] += "5)网络相关:\n"
        tsar_path = get_tsar_path(cache_data)
        if len(tsar_path) > 0:
            cmd = ('%s --tcp -i 1 -n 1 2>/dev/null'%(tsar_path))
            retrans = get_tsar_data(cache_data, cmd)
            index = 0
            highretran_num = 0
            need_diag = 0
            if len(retrans) > 0:
                retrans = retrans.splitlines()
                net_sum = ""
                for line in retrans:
                    line = line.strip()
                    if len(line) <= 0:
                        continue
                    if line.find('retran') > 0 and index == 0:
                        line = line.split()
                        i = 0
                        for item in line:
                            if item.strip() == 'retran':
                                    index = i
                                    break
                            i += 1
                    elif (line.startswith('Time') or line.startswith('MAX') or
                               line.startswith('MEAN') or line.startswith('MIN')):
                        continue
                    else:
                        try:
                            line = line.split()
                            retran = float(line[index])
                            if retran > ossre_config['net_retrans_thresh']:
                                highretran_num += 1
                                if highretran_num < 10:
                                    net_sum += "时间:%s,retran:%s\n"%(line[0],retran)
                        except:
                            traceback.print_exc()
                            pass
                if highretran_num > 0:
                    ret['fields']['SLI']['NET']['highretran_num']['value'] = highretran_num
                    ret['fields']['SLI']['NET']['highretran_num']['status'] = "critical"
                    ret['fields']['SLI']['NET']['highretran_num']['info'] = ("检查系统网络近一天内是否存在高重传情况，"
                        "当前网络重传率>%.2f%%的情况已出现%d分钟"%(ossre_config['net_retrans_thresh'],highretran_num))
                    ret['fields']['SLI']['NET']['highretran_num']['solution'] = DEFAULT_SOLUTION
                if len(net_sum) > 0:
                    summary += "网络存在高重传(重传率>30%%):\n%s"%(net_sum)
    
            if highretran_num > 0:
                ret['status'] = -1
    
            if len(summary) <= 0:
                summary = "None\n"
            else:

                ret['fields']['cust']['SLI']['highretran'] = {}
                ret['fields']['cust']['SLI']['highretran']['category'] = cust_const.highretran['category']
                ret['fields']['cust']['SLI']['highretran']['level'] = cust_const.highretran['level']
                ret['fields']['cust']['SLI']['highretran']['desc'] = cust_const.highretran['desc']
                ret['fields']['cust']['SLI']['highretran']['name'] = cust_const.highretran['name']
                ret['fields']['cust']['SLI']['highretran']['solution'] = ""
                ret['fields']['cust']['SLI']['highretran']['params'] = {}
                ret['fields']['cust']['SLI']['highretran']['params']['highretran_num'] = highretran_num
                ret['fields']['cust']['SLI']['highretran']['summary'] = summary

            ret['fields']['SLI']['summary'] += summary
    
    except Exception as e:
        print( 'check_net_indicator exception:',e)
        traceback.print_exc()
        pass

def check_misc_indicator(ret):
    try:
        summary = ""
        # check cgroup numbers
        ret['fields']['SLI']['MISC']['max_cgroup_num'] = {}
        ret['fields']['SLI']['MISC']['max_cgroup_num']['status'] = "normal"
        ret['fields']['SLI']['summary'] += "6)MISC:\n"
        cgroups = get_fs_value(cache_data, "/proc/cgroups").splitlines()
        cgroup_num = 0
        for cgroup in cgroups:
            try:
                cgroup = int(cgroup.split()[2])
                if cgroup > cgroup_num:
                    cgroup_num = cgroup
            except:
                pass
        ret['fields']['SLI']['MISC']['max_cgroup_num']['value'] = cgroup_num
        if cgroup_num > ossre_config['max_cgroup_num']:
            ret['status'] = -1
            summary += "cgroup数量过大达到%s,容易造成长时间关中断导致RT高和sys高\n"%(cgroup_num)
            ret['fields']['SLI']['MISC']['max_cgroup_num']['status'] = "warning"
            ret['fields']['SLI']['MISC']['max_cgroup_num']['info'] = ("检查系统的cgroup最大数量,"
                "如果大于%d,就告警,cgroup数量过大,容易造成长时间关中断导致RT高和sys高" % (ossre_config['max_cgroup_num']))
            ret['fields']['SLI']['MISC']['max_cgroup_num']['solution'] = ("建议排查是否有空的cgroup目录，"
                "需要清理，或者容器部署数量是否过多，建议迁移")
            if run_diag == 1:
                summary += cgroupcheck.num_check()

        if len(summary) <= 0:
            summary = "None\n"
        else:
            ret['fields']['cust']['SLI']['highcgroup'] = {}
            ret['fields']['cust']['SLI']['highcgroup']['category'] = "MISC"
            ret['fields']['cust']['SLI']['highcgroup']['level'] = "warning"
            ret['fields']['cust']['SLI']['highcgroup']['desc'] = ("cgroup数量过大"
                "容易造成长时间关中断导致RT高和sys高")
            ret['fields']['cust']['SLI']['highcgroup']['name'] = "cgroup数量高检查"
            ret['fields']['cust']['SLI']['highcgroup']['solution'] = ""
            ret['fields']['cust']['SLI']['highcgroup']['params'] = {}
            ret['fields']['cust']['SLI']['highcgroup']['params']['cgroup_num'] = cgroup_num
            ret['fields']['cust']['SLI']['highcgroup']['summary'] = summary

        ret['fields']['SLI']['summary'] += summary

    except Exception as e:
        print( 'check_misc_indicator exception:',e)
        traceback.print_exc()
        pass

def check_sched_params(ret):
    try:
        summary = ""
        kernel_ver = get_fs_value(cache_data, '/proc/version')
        ret['fields']['CONFIG']['PARAM']['SCHED']['cfsquota'] = {}
        ret['fields']['CONFIG']['PARAM']['SCHED']['cfsquota']['status'] = "normal"
        ret['fields']['CONFIG']['PARAM']['SCHED']['pid_max'] = {}
        ret['fields']['CONFIG']['PARAM']['SCHED']['pid_max']['status'] = "normal"
        ret['fields']['CONFIG']['PARAM']['SCHED']['softlockup_panic'] = {}
        ret['fields']['CONFIG']['PARAM']['SCHED']['softlockup_panic']['status'] = "normal"
        ret['fields']['CONFIG']['PARAM']['SCHED']['hung_task_panic'] = {}
        ret['fields']['CONFIG']['PARAM']['SCHED']['hung_task_panic']['status'] = "normal"
        ret['fields']['CONFIG']['summary'] += "1)调度相关:\n"

        cmd = "ps -eLf |wc -l"
        task_num = get_cmddata(cache_data, cmd)
        pid_max = get_fs_value(cache_data, "/proc/sys/kernel/pid_max")
        if (len(pid_max) > 0 and int(pid_max) < 131072) or (int(task_num) > int(pid_max)/3*2):
            ret['fields']['CONFIG']['PARAM']['SCHED']['pid_max']['value'] = int(pid_max)
            ret['fields']['CONFIG']['PARAM']['SCHED']['pid_max']['status'] = "warning"
            ret['fields']['CONFIG']['PARAM']['SCHED']['pid_max']['info'] = ("检查机器的/proc/sys/kernel/pid_max的值，"
                "如果小于131072，建议设置大一些，如果太小的话，容易导致创建新进程失败")
            ret['fields']['CONFIG']['PARAM']['SCHED']['pid_max']['solution'] = "把机器的/proc/sys/kernel/pid_max的值调大，范围为[301,4194304]"
            summary += "该机器任务数量为%s, pid_max=%s设置过小容易导致创建新进程失败和ssh失联,建议把机器的/proc/sys/kernel/pid_max的值调大，范围为[301,4194304]\n"%(task_num,pid_max)

            ret['fields']['cust']['CONFIG']['small_pid_max'] = {}
            ret['fields']['cust']['CONFIG']['small_pid_max']['category'] = cust_const.small_pid_max['category']
            ret['fields']['cust']['CONFIG']['small_pid_max']['level'] = cust_const.small_pid_max['level']
            ret['fields']['cust']['CONFIG']['small_pid_max']['name'] = cust_const.small_pid_max['name']
            ret['fields']['cust']['CONFIG']['small_pid_max']['desc'] = cust_const.small_pid_max['desc']
            ret['fields']['cust']['CONFIG']['small_pid_max']['solution'] = cust_const.small_pid_max['solution']
            ret['fields']['cust']['CONFIG']['small_pid_max']['params'] = {}
            ret['fields']['cust']['CONFIG']['small_pid_max']['params']['pid_max'] = pid_max
            ret['fields']['cust']['CONFIG']['small_pid_max']['params']['task_num'] = task_num
            ret['fields']['cust']['CONFIG']['small_pid_max']['summary'] = (
                cust_const.small_pid_max['summary_format']%(ret['fields']['cust']['CONFIG']['small_pid_max']['params']['task_num'],
                    ret['fields']['cust']['CONFIG']['small_pid_max']['params']['pid_max']))

        softlockup_panic = get_fs_value(cache_data, "/proc/sys/kernel/softlockup_panic")
        if int(softlockup_panic) == 1:
            ret['fields']['CONFIG']['PARAM']['SCHED']['softlockup_panic']['value'] = int(softlockup_panic)
            ret['fields']['CONFIG']['PARAM']['SCHED']['softlockup_panic']['status'] = "critical"
            ret['fields']['CONFIG']['PARAM']['SCHED']['softlockup_panic']['info'] = ("softlockup_panic打开，容易造成频繁宕机，建议关闭")
            ret['fields']['CONFIG']['PARAM']['SCHED']['softlockup_panic']['solution'] = "关闭softlockup_panic，sudo echo 0 > /proc/sys/kernel/softlockup_panic"
            summary += "该机器softlockup_panic打开，容易造成频繁宕机，建议关闭\n"

            ret['fields']['cust']['CONFIG']['softlockup_panic'] = {}
            ret['fields']['cust']['CONFIG']['softlockup_panic']['category'] = cust_const.softlockup_panic['category']
            ret['fields']['cust']['CONFIG']['softlockup_panic']['level'] = cust_const.softlockup_panic['level']
            ret['fields']['cust']['CONFIG']['softlockup_panic']['name'] = cust_const.softlockup_panic['name']
            ret['fields']['cust']['CONFIG']['softlockup_panic']['desc'] = cust_const.softlockup_panic['desc']
            ret['fields']['cust']['CONFIG']['softlockup_panic']['solution'] = cust_const.softlockup_panic['solution']
            ret['fields']['cust']['CONFIG']['softlockup_panic']['params'] = {}
            ret['fields']['cust']['CONFIG']['softlockup_panic']['params']['softlockup_panic'] = int(softlockup_panic)
            ret['fields']['cust']['CONFIG']['softlockup_panic']['summary'] = (cust_const.softlockup_panic['summary_format'])

        hung_task_panic = get_fs_value(cache_data, "/proc/sys/kernel/hung_task_panic")
        if int(hung_task_panic) == 1:
            ret['fields']['CONFIG']['PARAM']['SCHED']['hung_task_panic']['value'] = int(hung_task_panic)
            ret['fields']['CONFIG']['PARAM']['SCHED']['hung_task_panic']['status'] = "critical"
            ret['fields']['CONFIG']['PARAM']['SCHED']['hung_task_panic']['info'] = ("hung_task_panic打开，容易造成频繁宕机，建议关闭")
            ret['fields']['CONFIG']['PARAM']['SCHED']['hung_task_panic']['solution'] = "关闭hung_task_panic，sudo echo 0 > /proc/sys/kernel/hung_task_panic"
            summary += "该机器hung_task_panicc打开，容易造成频繁宕机，建议关闭\n"

            ret['fields']['cust']['CONFIG']['hung_task_panic'] = {}
            ret['fields']['cust']['CONFIG']['hung_task_panic']['category'] = cust_const.hung_task_panic['category']
            ret['fields']['cust']['CONFIG']['hung_task_panic']['level'] = cust_const.hung_task_panic['level']
            ret['fields']['cust']['CONFIG']['hung_task_panic']['name'] = cust_const.hung_task_panic['name']
            ret['fields']['cust']['CONFIG']['hung_task_panic']['desc'] = cust_const.hung_task_panic['desc']
            ret['fields']['cust']['CONFIG']['hung_task_panic']['solution'] = cust_const.hung_task_panic['solution']
            ret['fields']['cust']['CONFIG']['hung_task_panic']['params'] = {}
            ret['fields']['cust']['CONFIG']['hung_task_panic']['params']['hung_task_panic'] = int(hung_task_panic)
            ret['fields']['cust']['CONFIG']['hung_task_panic']['summary'] = (cust_const.hung_task_panic['summary_format'])

        if len(summary) <= 0:
            summary = "None\n"
        ret['fields']['CONFIG']['summary'] += summary

    except Exception as e:
        print( 'check_sched_params exception:',e)
        traceback.print_exc()
        pass

def check_mem_params(ret):
    try:
        summary = ""
        ret['fields']['CONFIG']['PARAM']['MEM']['THP'] = {}
        ret['fields']['CONFIG']['PARAM']['MEM']['THP']['status'] = "normal"
        ret['fields']['CONFIG']['PARAM']['MEM']['THP']['value'] = {}
        ret['fields']['CONFIG']['PARAM']['MEM']['min_free_kbytes'] = {}
        ret['fields']['CONFIG']['PARAM']['MEM']['min_free_kbytes']['status'] = "normal"
        ret['fields']['CONFIG']['PARAM']['SCHED']['panic_on_oom'] = {}
        ret['fields']['CONFIG']['PARAM']['SCHED']['panic_on_oom']['status'] = "normal"
        ret['fields']['CONFIG']['summary'] += "2)内存相关:\n"

        # /proc/sys/vm/min_free_kbytes
        min_free_kbytes = get_fs_value(cache_data, "/proc/sys/vm/min_free_kbytes")
        if len(min_free_kbytes) > 0:
            min_free_kbytes = int(min_free_kbytes)
            ret['fields']['CONFIG']['PARAM']['MEM']['min_free_kbytes']['value'] = min_free_kbytes
            if min_free_kbytes < 2000000:
                ret['fields']['CONFIG']['PARAM']['MEM']['min_free_kbytes']['status'] = "warning"
                ret['fields']['CONFIG']['PARAM']['MEM']['min_free_kbytes']['info'] = ("检查/proc/sys/vm/min_free_kbytes参数，"
                    "小于2G就告警，该参数设置过小，容易导致频繁的directreclaim，导致load高风险，建议调整大小")
                ret['fields']['CONFIG']['PARAM']['MEM']['min_free_kbytes']['solution'] = "建议调整该参数为系统总内存大小的1-3%，且大于等于2G."
                summary += ("该机器min_free_kbytes=%skB设置过小容易频繁directreclaim,"
                        "建议调整该参数为系统总内存大小的1-3%%\n"%(min_free_kbytes))

            ret['fields']['cust']['CONFIG']['min_free_kbytes'] = {}
            ret['fields']['cust']['CONFIG']['min_free_kbytes']['category'] = cust_const.min_free_kbytes['category']
            ret['fields']['cust']['CONFIG']['min_free_kbytes']['level'] = cust_const.min_free_kbytes['level']
            ret['fields']['cust']['CONFIG']['min_free_kbytes']['name'] = cust_const.min_free_kbytes['name']
            ret['fields']['cust']['CONFIG']['min_free_kbytes']['desc'] = cust_const.min_free_kbytes['desc']
            ret['fields']['cust']['CONFIG']['min_free_kbytes']['solution'] = cust_const.min_free_kbytes['solution']
            ret['fields']['cust']['CONFIG']['min_free_kbytes']['params'] = {}
            ret['fields']['cust']['CONFIG']['min_free_kbytes']['params']['min_free_kbytes_value'] = min_free_kbytes
            ret['fields']['cust']['CONFIG']['min_free_kbytes']['summary'] = (
                cust_const.min_free_kbytes['summary_format']%(ret['fields']['cust']['CONFIG']['min_free_kbytes']['params']['min_free_kbytes_value']))

        sn = ''
        data = {}
        filepath = '/sys/fs/cgroup/cpuset/cpuset.mems'
        if os.path.isfile(filepath):
            cmd = "cat %s 2>/dev/null"%filepath
            root_mems = collect_data.get_cmddata(sn, data, cmd).strip()
            if root_mems != '0':
                cmd = "find %s -maxdepth 5 -name cpuset.mems 2>/dev/null"%filepath.strip('cpuset.mems')
                mempaths = collect_data.get_cmddata(sn, data, cmd).splitlines()
                for path in mempaths:
                    if os.path.isfile(path):
                        cmd = "cat %s 2>/dev/null"%path
                        mid_mems = collect_data.get_cmddata(sn, data, cmd)
                        if len(mid_mems) > 0:
                            mems = mid_mems.strip()
                            if len(mems) > 0 and mems != root_mems:
                                ret['fields']['CONFIG']['PARAM']['MEM']['cpuset.mems_inconsist'] = 1
                                summary += "存在某些cpuset cgroup的cpuset.mems设置和根组不相同，可能会存在节点OOM的风险\n"

                                ret['fields']['cust']['CONFIG']['cpuset.mems_inconsist'] = {}
                                ret['fields']['cust']['CONFIG']['cpuset.mems_inconsist']['category'] = cust_const.cpuset_mems_inconsist['category']
                                ret['fields']['cust']['CONFIG']['cpuset.mems_inconsist']['level'] = cust_const.cpuset_mems_inconsist['level']
                                ret['fields']['cust']['CONFIG']['cpuset.mems_inconsist']['name'] = cust_const.cpuset_mems_inconsist['name']
                                ret['fields']['cust']['CONFIG']['cpuset.mems_inconsist']['desc'] = cust_const.cpuset_mems_inconsist['desc']
                                ret['fields']['cust']['CONFIG']['cpuset.mems_inconsist']['solution'] = cust_const.cpuset_mems_inconsist['solution']
                                ret['fields']['cust']['CONFIG']['cpuset.mems_inconsist']['summary'] = cust_const.cpuset_mems_inconsist['summary_format']

                                break

        panic_on_oom = get_fs_value(cache_data, "/proc/sys/vm/panic_on_oom")
        if int(panic_on_oom) == 1:
            ret['fields']['CONFIG']['PARAM']['SCHED']['panic_on_oom']['value'] = int()
            ret['fields']['CONFIG']['PARAM']['SCHED']['panic_on_oom']['status'] = "critical"
            ret['fields']['CONFIG']['PARAM']['SCHED']['panic_on_oom']['info'] = ("panic_on_oom打开，容易造成频繁宕机，建议关闭")
            ret['fields']['CONFIG']['PARAM']['SCHED']['panic_on_oom']['solution'] = "关闭panic_on_oom，sudo echo 0 > /proc/sys/vm/panic_on_oom"
            summary += "该机器panic_on_oomc打开，容易造成频繁宕机，建议关闭\n"

            ret['fields']['cust']['CONFIG']['panic_on_oom'] = {}
            ret['fields']['cust']['CONFIG']['panic_on_oom']['category'] = cust_const.panic_on_oom['category']
            ret['fields']['cust']['CONFIG']['panic_on_oom']['level'] = cust_const.panic_on_oom['level']
            ret['fields']['cust']['CONFIG']['panic_on_oom']['name'] = cust_const.panic_on_oom['name']
            ret['fields']['cust']['CONFIG']['panic_on_oom']['desc'] = cust_const.panic_on_oom['desc']
            ret['fields']['cust']['CONFIG']['panic_on_oom']['solution'] = cust_const.panic_on_oom['solution']
            ret['fields']['cust']['CONFIG']['panic_on_oom']['params'] = {}
            ret['fields']['cust']['CONFIG']['panic_on_oom']['params']['panic_on_oom'] = int(panic_on_oom)
            ret['fields']['cust']['CONFIG']['panic_on_oom']['summary'] = (cust_const.panic_on_oom['summary_format'])

        if len(summary) <= 0:
            summary = "None\n"
        ret['fields']['CONFIG']['summary'] += summary
    except Exception as e:
        print( 'check_mem_params exception:',e)
        traceback.print_exc()
        pass

def check_io_params(ret):
    try:
        summary = ""
        ret['fields']['CONFIG']['summary'] += "3)IO相关:\n"
        # mount挂载参数dioread_nolock & nodelalloc
        ret['fields']['CONFIG']['PARAM']['IO']['mount_option'] = {}
        ret['fields']['CONFIG']['PARAM']['IO']['mount_option']['value'] = []
        ret['fields']['CONFIG']['PARAM']['IO']['mount_option']['status'] = "normal"
        mountinfo = get_fs_value(cache_data, "/proc/mounts").splitlines()
        for line in mountinfo:
            if "dioread_nolock" in line and "nodelalloc" in line:
                ret['fields']['CONFIG']['PARAM']['IO']['mount_option']['value'].append(line)
                ret['fields']['CONFIG']['PARAM']['IO']['mount_option']['status'] = "critical"
                ret['fields']['CONFIG']['PARAM']['IO']['mount_option']['info'] = ("检查mount的挂载参数，"
                    "如果dioread_nolock和nodelalloc同时使用，就告警")
                ret['fields']['CONFIG']['PARAM']['IO']['mount_option']['solution'] = ("修改mount的挂载参数,"
                    "dioread_nolock和nodelalloc不能同时使用")
                summary += "dioread_nolock和nodelalloc不能同时使用,建议修改mount的挂载参数\n"

                ret['fields']['cust']['CONFIG']['mount_option'] = {}
                ret['fields']['cust']['CONFIG']['mount_option']['category'] = cust_const.mount_option['category']
                ret['fields']['cust']['CONFIG']['mount_option']['level'] = cust_const.mount_option['level']
                ret['fields']['cust']['CONFIG']['mount_option']['name'] = cust_const.mount_option['name']
                ret['fields']['cust']['CONFIG']['mount_option']['desc'] = cust_const.mount_option['desc']
                ret['fields']['cust']['CONFIG']['mount_option']['solution'] = cust_const.mount_option['solution']
                ret['fields']['cust']['CONFIG']['mount_option']['summary'] = cust_const.mount_option['summary_format']

        if len(summary) <= 0:
            summary = "None\n"
        ret['fields']['CONFIG']['summary'] += summary

    except Exception as e:
        print( 'check_io_params exception:',e)
        traceback.print_exc()
        pass

def check_net_params(ret):
    try:
        summary = ""
        ret['fields']['CONFIG']['summary'] += "4)网络相关:\n"
        # NET
        tcp_fack = get_fs_value(cache_data, "/proc/sys/net/ipv4/tcp_fack")
        if len(tcp_fack) > 0:
            ret['fields']['CONFIG']['PARAM']['NET']['tcp_fack'] = {}
            ret['fields']['CONFIG']['PARAM']['NET']['tcp_fack']['value'] = tcp_fack
            if int(tcp_fack) != 1:
                summary += ("/proc/sys/net/ipv4/tcp_fack 推荐设置为1\n")

                ret['fields']['cust']['CONFIG']['tcp_fack'] = {}
                ret['fields']['cust']['CONFIG']['tcp_fack']['category'] = cust_const.tcp_fack['category']
                ret['fields']['cust']['CONFIG']['tcp_fack']['level'] = cust_const.tcp_fack['level']
                ret['fields']['cust']['CONFIG']['tcp_fack']['name'] = cust_const.tcp_fack['name']
                ret['fields']['cust']['CONFIG']['tcp_fack']['desc'] = cust_const.tcp_fack['desc']
                ret['fields']['cust']['CONFIG']['tcp_fack']['solution'] = cust_const.tcp_fack['solution']
                ret['fields']['cust']['CONFIG']['tcp_fack']['params'] = {}
                ret['fields']['cust']['CONFIG']['tcp_fack']['params']['tcp_fack_value'] = tcp_fack
                ret['fields']['cust']['CONFIG']['tcp_fack']['summary'] = cust_const.tcp_fack['summary_format']

        tcp_recovery = get_fs_value(cache_data, "/proc/sys/net/ipv4/tcp_recovery")
        if len(tcp_recovery) > 0:
            ret['fields']['CONFIG']['PARAM']['NET']['tcp_recovery'] = {}
            ret['fields']['CONFIG']['PARAM']['NET']['tcp_recovery']['value'] = tcp_recovery
            if int(tcp_recovery) != 1:
                summary += ("/proc/sys/net/ipv4/tcp_recovery 推荐设置为1\n")

                ret['fields']['cust']['CONFIG']['tcp_recovery'] = {}
                ret['fields']['cust']['CONFIG']['tcp_recovery']['category'] = cust_const.tcp_recovery['category']
                ret['fields']['cust']['CONFIG']['tcp_recovery']['level'] = cust_const.tcp_recovery['level']
                ret['fields']['cust']['CONFIG']['tcp_recovery']['name'] = cust_const.tcp_recovery['name']
                ret['fields']['cust']['CONFIG']['tcp_recovery']['desc'] = cust_const.tcp_recovery['desc']
                ret['fields']['cust']['CONFIG']['tcp_recovery']['solution'] = cust_const.tcp_recovery['solution']
                ret['fields']['cust']['CONFIG']['tcp_recovery']['params'] = {}
                ret['fields']['cust']['CONFIG']['tcp_recovery']['params']['tcp_recovery_value'] = tcp_recovery
                ret['fields']['cust']['CONFIG']['tcp_recovery']['summary'] = cust_const.tcp_recovery['summary_format']

        tcp_tw_timeout = get_fs_value(cache_data, "/proc/sys/net/ipv4/tcp_tw_timeout")
        if len(tcp_tw_timeout) > 0:
            ret['fields']['CONFIG']['PARAM']['NET']['tcp_tw_timeout'] = {}
            ret['fields']['CONFIG']['PARAM']['NET']['tcp_tw_timeout']['value'] = tcp_tw_timeout
            if int(tcp_tw_timeout) != 3:
                summary += ("/proc/sys/net/ipv4/tcp_tw_timeout 推荐设置为3\n")

                ret['fields']['cust']['CONFIG']['tcp_tw_timeout'] = {}
                ret['fields']['cust']['CONFIG']['tcp_tw_timeout']['category'] = cust_const.tcp_tw_timeout['category']
                ret['fields']['cust']['CONFIG']['tcp_tw_timeout']['level'] = cust_const.tcp_tw_timeout['level']
                ret['fields']['cust']['CONFIG']['tcp_tw_timeout']['name'] = cust_const.tcp_tw_timeout['name']
                ret['fields']['cust']['CONFIG']['tcp_tw_timeout']['desc'] = cust_const.tcp_tw_timeout['desc']
                ret['fields']['cust']['CONFIG']['tcp_tw_timeout']['solution'] = cust_const.tcp_tw_timeout['solution']
                ret['fields']['cust']['CONFIG']['tcp_tw_timeout']['params'] = {}
                ret['fields']['cust']['CONFIG']['tcp_tw_timeout']['params']['tcp_tw_timeout_value'] = tcp_tw_timeout
                ret['fields']['cust']['CONFIG']['tcp_tw_timeout']['summary'] = cust_const.tcp_tw_timeout['summary_format']

        tcp_tw_reuse = get_fs_value(cache_data, "/proc/sys/net/ipv4/tcp_tw_reuse")
        if len(tcp_tw_reuse) > 0:
            ret['fields']['CONFIG']['PARAM']['NET']['tcp_tw_reuse'] = {}
            ret['fields']['CONFIG']['PARAM']['NET']['tcp_tw_reuse']['value'] = tcp_tw_reuse
            if int(tcp_tw_reuse) != 1:
                summary += ("/proc/sys/net/ipv4/tcp_tw_reuse 推荐设置为1\n")

                ret['fields']['cust']['CONFIG']['tcp_tw_reuse'] = {}
                ret['fields']['cust']['CONFIG']['tcp_tw_reuse']['category'] = cust_const.tcp_tw_reuse['category']
                ret['fields']['cust']['CONFIG']['tcp_tw_reuse']['level'] = cust_const.tcp_tw_reuse['level']
                ret['fields']['cust']['CONFIG']['tcp_tw_reuse']['name'] = cust_const.tcp_tw_reuse['name']
                ret['fields']['cust']['CONFIG']['tcp_tw_reuse']['desc'] = cust_const.tcp_tw_reuse['desc']
                ret['fields']['cust']['CONFIG']['tcp_tw_reuse']['solution'] = cust_const.tcp_tw_reuse['solution']
                ret['fields']['cust']['CONFIG']['tcp_tw_reuse']['params'] = {}
                ret['fields']['cust']['CONFIG']['tcp_tw_reuse']['params']['tcp_tw_reuse_value'] = tcp_tw_reuse
                ret['fields']['cust']['CONFIG']['tcp_tw_reuse']['summary'] = cust_const.tcp_tw_reuse['summary_format']

        tcp_tw_recycle = get_fs_value(cache_data, "/proc/sys/net/ipv4/tcp_tw_recycle")
        if len(tcp_tw_recycle) > 0:
            ret['fields']['CONFIG']['PARAM']['NET']['tcp_tw_recycle'] = {}
            ret['fields']['CONFIG']['PARAM']['NET']['tcp_tw_recycle']['value'] = tcp_tw_recycle
            if int(tcp_tw_recycle) != 0:
                summary += ("/proc/sys/net/ipv4/tcp_tw_recycle 推荐设置为0\n")

                ret['fields']['cust']['CONFIG']['tcp_tw_recycle'] = {}
                ret['fields']['cust']['CONFIG']['tcp_tw_recycle']['category'] = cust_const.tcp_tw_recycle['category']
                ret['fields']['cust']['CONFIG']['tcp_tw_recycle']['level'] = cust_const.tcp_tw_recycle['level']
                ret['fields']['cust']['CONFIG']['tcp_tw_recycle']['name'] = cust_const.tcp_tw_recycle['name']
                ret['fields']['cust']['CONFIG']['tcp_tw_recycle']['desc'] = cust_const.tcp_tw_recycle['desc']
                ret['fields']['cust']['CONFIG']['tcp_tw_recycle']['solution'] = cust_const.tcp_tw_recycle['solution']
                ret['fields']['cust']['CONFIG']['tcp_tw_recycle']['params'] = {}
                ret['fields']['cust']['CONFIG']['tcp_tw_recycle']['params']['tcp_tw_recycle_value'] = tcp_tw_recycle
                ret['fields']['cust']['CONFIG']['tcp_tw_recycle']['summary'] = cust_const.tcp_tw_recycle['summary_format']

        tcp_sack = get_fs_value(cache_data, "/proc/sys/net/ipv4/tcp_sack")
        if len(tcp_sack) > 0:
            ret['fields']['CONFIG']['PARAM']['NET']['tcp_sack'] = {}
            ret['fields']['CONFIG']['PARAM']['NET']['tcp_sack']['value'] = tcp_sack
            if int(tcp_sack) != 1:
                summary += ("/proc/sys/net/ipv4/tcp_sack 推荐设置为1\n")

                ret['fields']['cust']['CONFIG']['tcp_sack'] = {}
                ret['fields']['cust']['CONFIG']['tcp_sack']['category'] = cust_const.tcp_sack['category']
                ret['fields']['cust']['CONFIG']['tcp_sack']['level'] = cust_const.tcp_sack['level']
                ret['fields']['cust']['CONFIG']['tcp_sack']['name'] = cust_const.tcp_sack['name']
                ret['fields']['cust']['CONFIG']['tcp_sack']['desc'] = cust_const.tcp_sack['desc']
                ret['fields']['cust']['CONFIG']['tcp_sack']['solution'] = cust_const.tcp_sack['solution']
                ret['fields']['cust']['CONFIG']['tcp_sack']['params'] = {}
                ret['fields']['cust']['CONFIG']['tcp_sack']['params']['tcp_sack_value'] = tcp_sack
                ret['fields']['cust']['CONFIG']['tcp_sack']['summary'] = cust_const.tcp_sack['summary_format']

        tcp_slow_start_after_idle = get_fs_value(cache_data, "/proc/sys/net/ipv4/tcp_slow_start_after_idle")
        if len(tcp_slow_start_after_idle) > 0:
            ret['fields']['CONFIG']['PARAM']['NET']['tcp_slow_start_after_idle'] = {}
            ret['fields']['CONFIG']['PARAM']['NET']['tcp_slow_start_after_idle']['value'] = tcp_slow_start_after_idle

        ip_early_demux = get_fs_value(cache_data, "/proc/sys/net/ipv4/ip_early_demux")
        ret['fields']['CONFIG']['PARAM']['NET']['ip_early_demux'] = {}
        ret['fields']['CONFIG']['PARAM']['NET']['ip_early_demux']['status'] = "normal"
        if len(ip_early_demux) > 0:
            ret['fields']['CONFIG']['PARAM']['NET']['ip_early_demux']['value'] = ip_early_demux

        ipfrag_high_thresh = get_fs_value(cache_data, "/proc/sys/net/ipv4/ipfrag_high_thresh")
        ret['fields']['CONFIG']['PARAM']['NET']['ipfrag_high_thresh'] = {}
        ret['fields']['CONFIG']['PARAM']['NET']['ipfrag_high_thresh']['status'] = "normal"
        if len(ipfrag_high_thresh) > 0:
            ret['fields']['CONFIG']['PARAM']['NET']['ipfrag_high_thresh']['value'] = ipfrag_high_thresh

        if len(summary) <= 0:
            summary = "None\n"
        ret['fields']['CONFIG']['summary'] += summary

    except Exception as e:
        print( 'check_net_params exception:',e)
        traceback.print_exc()
        pass

def check_misc_params(ret):
    summary = ""
    ret['fields']['CONFIG']['PARAM']['MISC']['ibrs_enabled'] = {}
    ret['fields']['CONFIG']['PARAM']['MISC']['ibrs_enabled']['status'] = "normal"
    ret['fields']['CONFIG']['PARAM']['MISC']['ibpb_enabled'] = {}
    ret['fields']['CONFIG']['PARAM']['MISC']['ibpb_enabled']['status'] = "normal"
    ret['fields']['CONFIG']['PARAM']['MISC']['cstate'] = {}
    ret['fields']['CONFIG']['PARAM']['MISC']['cstate']['value'] = {}
    ret['fields']['CONFIG']['PARAM']['MISC']['cstate']['status'] = "normal"
    ret['fields']['CONFIG']['PARAM']['MISC']['cstate']['info'] = ("检查cmdline，是否正确配置了intel的cstate，"
        "如果不正确，就告警。建议关闭intel的cstate状态")
    ret['fields']['CONFIG']['PARAM']['MISC']['cstate']['solution'] = ("修改系统grub配置，"
        "增加processor.max_cstate=1 intel_idle.max_cstate=0选项")
    ret['fields']['CONFIG']['summary'] += "5)MISC:\n"
    try:
        cmd = 'uname -p 2>/dev/null'
        platform = get_cmddata(cache_data, cmd)
        if platform != "x86_64":
            return

        # Check Intel CPU vulnerability settings
        ibrs = get_fs_value(cache_data, "/sys/kernel/debug/x86/ibrs_enabled")
        if len(ibrs) > 0:
            ret['fields']['CONFIG']['PARAM']['MISC']['ibrs_enabled']['value'] = ibrs
            if int(ibrs) == 1:
                ret['fields']['CONFIG']['PARAM']['MISC']['ibrs_enabled']['status'] = "warning"
                ret['fields']['CONFIG']['PARAM']['MISC']['ibrs_enabled']['info'] = ("检查/sys/kernel/debug/x86/ibrs_enabled接口的值，"
                    "如果配置为1，就告警，容易导致性能损耗")
                ret['fields']['CONFIG']['PARAM']['MISC']['ibrs_enabled']['solution'] = "把/sys/kernel/debug/x86/ibrs_enabled接口设置为0"
                summary += "该机器设置ibrs_enabled导致性能损耗,建议关闭\n"

                ret['fields']['cust']['CONFIG']['ibrs_enabled'] = {}
                ret['fields']['cust']['CONFIG']['ibrs_enabled']['category'] = cust_const.ibrs_enabled['category']
                ret['fields']['cust']['CONFIG']['ibrs_enabled']['level'] = cust_const.ibrs_enabled['level']
                ret['fields']['cust']['CONFIG']['ibrs_enabled']['name'] = cust_const.ibrs_enabled['name']
                ret['fields']['cust']['CONFIG']['ibrs_enabled']['desc'] = cust_const.ibrs_enabled['desc']
                ret['fields']['cust']['CONFIG']['ibrs_enabled']['solution'] = cust_const.ibrs_enabled['solution']
                ret['fields']['cust']['CONFIG']['ibrs_enabled']['summary'] = cust_const.ibrs_enabled['summary_format']

        ibpb = get_fs_value(cache_data, "/sys/kernel/debug/x86/ibpb_enabled")
        if len(ibpb) > 0:
            ret['fields']['CONFIG']['PARAM']['MISC']['ibpb_enabled']['value'] = ibpb
            if int(ibpb) == 1:
                ret['fields']['CONFIG']['PARAM']['MISC']['ibpb_enabled']['status'] = "warning"
                ret['fields']['CONFIG']['PARAM']['MISC']['ibpb_enabled']['info'] = ("检查/sys/kernel/debug/x86/ibpb_enabled接口的值，"
                    "如果配置为1，就告警，容易导致性能损耗")
                ret['fields']['CONFIG']['PARAM']['MISC']['ibpb_enabled']['solution'] = "把/sys/kernel/debug/x86/ibpb_enabled接口设置为0"
                summary += "该机器设置ibpb_enabled导致性能损耗,建议关闭\n"

                ret['fields']['cust']['CONFIG']['ibpb_enabled'] = {}
                ret['fields']['cust']['CONFIG']['ibpb_enabled']['category'] = cust_const.ibpb_enabled['category']
                ret['fields']['cust']['CONFIG']['ibpb_enabled']['level'] = cust_const.ibpb_enabled['level']
                ret['fields']['cust']['CONFIG']['ibpb_enabled']['name'] = cust_const.ibpb_enabled['name']
                ret['fields']['cust']['CONFIG']['ibpb_enabled']['desc'] = cust_const.ibpb_enabled['desc']
                ret['fields']['cust']['CONFIG']['ibpb_enabled']['solution'] = cust_const.ibpb_enabled['solution']
                ret['fields']['cust']['CONFIG']['ibpb_enabled']['summary'] = cust_const.ibpb_enabled['summary_format']
        if len(summary) <= 0:
            summary = "None\n"
        ret['fields']['CONFIG']['summary'] += summary

    except Exception as e:
        print( 'check_misc_params exception:',e)
        traceback.print_exc()
        pass

def check_hotfix(ret):
    try:
        summary = ""
        ret['fields']['CONFIG']['HOTFIX'] = {}
        ret['fields']['CONFIG']['HOTFIX']['missed_hotfix'] = {}
        ret['fields']['CONFIG']['HOTFIX']['missed_hotfix']['status'] = "normal"
        ret['fields']['CONFIG']['HOTFIX']['conflict_hotfix'] = {}
        ret['fields']['CONFIG']['HOTFIX']['conflict_hotfix']['status'] = "normal"
        ret['fields']['CONFIG']['summary'] += "6)Hotfix相关:\n"
        # Check whether high risk hotfix missed
        hotfixes = []
        cmd = 'khotfix-view -r 2>/dev/null'
        hotfix_info = get_cmddata(cache_data, cmd)
        if len(hotfix_info) > 0:
            hotfix_info = hotfix_info.splitlines()
            for line in hotfix_info:
                hotfix = line.split()[0]
                hotfixes.append(hotfix)
        need_hotfixes = get_need_hotfix()
        miss_hotfixes = []
        for hotfix in need_hotfixes:
            if hotfix not in hotfixes:
                miss_hotfixes.append(hotfix)
        if len(miss_hotfixes) > 0:
            ret['fields']['CONFIG']['HOTFIX']['missed_hotfix']['value'] = miss_hotfixes
            ret['fields']['CONFIG']['HOTFIX']['missed_hotfix']['status'] = "warning"
            ret['fields']['CONFIG']['HOTFIX']['missed_hotfix']['info'] = ("检查系统是否没有安装一些重要的，"
                "容易引起系统宕机的基础hotfix, 缺少的hotfix集合："+str(miss_hotfixes))
            ret['fields']['CONFIG']['HOTFIX']['missed_hotfix']['solution'] = "建议安装这些重要的hotfix"
            info = {"list":miss_hotfixes}
            summary += "该机器未部署缺省hotfix列表,建议安装这些重要的hotfix:%s\n"%(json.dumps(info,ensure_ascii=False))

            ret['fields']['cust']['CONFIG']['missed_hotfix'] = {}
            ret['fields']['cust']['CONFIG']['missed_hotfix']['category'] = cust_const.missed_hotfix['category']
            ret['fields']['cust']['CONFIG']['missed_hotfix']['level'] = cust_const.missed_hotfix['level']
            ret['fields']['cust']['CONFIG']['missed_hotfix']['name'] = cust_const.missed_hotfix['name']
            ret['fields']['cust']['CONFIG']['missed_hotfix']['desc'] = cust_const.missed_hotfix['desc']
            ret['fields']['cust']['CONFIG']['missed_hotfix']['solution'] = cust_const.missed_hotfix['solution']
            ret['fields']['cust']['CONFIG']['missed_hotfix']['summary'] = (
                cust_const.missed_hotfix['summary_format']%(json.dumps(info,ensure_ascii=False)))

        # Check hotfix confliction
        all_funcs = set()
        kpatch_funcs = {}
        conflicts = set()
        if os.path.exists("/sys/kernel/kpatch/patches/"):
            for subdir, dirs, files in os.walk("/sys/kernel/kpatch/patches/"):
                if subdir.endswith('functions'):
                    patch = subdir.split('/')[-2]
                    for func in dirs:
                        if func in all_funcs:
                            for item in kpatch_funcs:
                                if func in kpatch_funcs[item]:
                                    conflicts.add("%s conflicts with %s"%(patch,item))
                        else:
                            all_funcs.add(func)

                        if patch not in kpatch_funcs:
                            kpatch_funcs[patch] = []
                        kpatch_funcs[patch].append(func)
        elif os.path.exists("/sys/kernel/livepatch/"):
            for subdir, dirs, files in os.walk("/sys/kernel/livepatch/"):
                patch = subdir.split('/')[-2]
                if patch.startswith('kpatch_'):
                    for func in dirs:
                        if func in all_funcs:
                            for item in kpatch_funcs:
                                if func in kpatch_funcs[item]:
                                    conflicts.add("%s conflicts with %s"%(patch,item))
                        else:
                            all_funcs.add(func)

                        if patch not in kpatch_funcs:
                            kpatch_funcs[patch] = []
                        kpatch_funcs[patch].append(func)

        if len(conflicts):
            ret['fields']['CONFIG']['HOTFIX']['conflict_hotfix']['value'] = list(conflicts)
            ret['fields']['CONFIG']['HOTFIX']['conflict_hotfix']['status'] = "warning"
            ret['fields']['CONFIG']['HOTFIX']['conflict_hotfix']['info'] = ("检查系统已安装hotfix里面，"
                "是否存在hotfix冲突的情况，如果存在，需要分析是否合理，否则会导致部分hotfix功能被覆盖的情况，"
                "当前hotfix冲突情况："+str(list(conflicts)))
            ret['fields']['CONFIG']['HOTFIX']['conflict_hotfix']['solution'] = DEFAULT_SOLUTION
            info = {"list":list(conflicts)}
            conf_sum = ("该机器部署如下hotfix存在冲突,建议联系内核支持同学处理:%s\n"%(json.dumps(info,ensure_ascii=False)))
            summary += conf_sum

            ret['fields']['cust']['CONFIG']['conflict_hotfix'] = {}
            ret['fields']['cust']['CONFIG']['conflict_hotfix']['category'] = cust_const.conflict_hotfix['category']
            ret['fields']['cust']['CONFIG']['conflict_hotfix']['level'] = cust_const.conflict_hotfix['level']
            ret['fields']['cust']['CONFIG']['conflict_hotfix']['name'] = cust_const.conflict_hotfix['name']
            ret['fields']['cust']['CONFIG']['conflict_hotfix']['desc'] = cust_const.conflict_hotfix['desc']
            ret['fields']['cust']['CONFIG']['conflict_hotfix']['solution'] = cust_const.conflict_hotfix['solution']
            ret['fields']['cust']['CONFIG']['conflict_hotfix']['summary'] = (
                cust_const.conflict_hotfix['summary_format']%(json.dumps(info,ensure_ascii=False)))

        if len(ret['fields']['CONFIG']['HOTFIX']) > 0:
            ret['status'] = -1

        if len(summary) <= 0:
            summary = "None\n"
        ret['fields']['CONFIG']['summary'] += summary

    except Exception as e:
        print( 'check_hotfix exception:',e)
        traceback.print_exc()
        pass

def get_sysinfo(result):
    try:
        result["summary"] += "\n系统信息:\n\n"
        result['SYSINFO']['cpuinfo'] = {}
        cmd = 'cat /etc/alios-version 2>/dev/null'
        result['SYSINFO']['os_version'] = get_cmddata(cache_data, cmd)
        cmd = "uname -r"
        result['SYSINFO']['kernel_version'] = get_cmddata(cache_data, cmd)
        result['SYSINFO']['kernel_cmdline'] = get_fs_value(cache_data, "/proc/cmdline")
        result["summary"] += "内核版本:%s\n"%(result['SYSINFO']['kernel_version'])
        cmd = "cat /sys/devices/system/node/online"
        result['SYSINFO']['cpuinfo']['numa'] = get_cmddata(cache_data, cmd)

        cmd = """grep 'physical id' /proc/cpuinfo | awk -F: '{print $2 | "sort -un"}' | wc -l"""
        result['SYSINFO']['cpuinfo']['socket_number'] = get_cmddata(cache_data, cmd)
        cpuinfo = get_fs_value(cache_data, "/proc/cpuinfo")
        if len(cpuinfo) > 0:
            cpuinfo = cpuinfo.splitlines()
            cpuinfo = cpuinfo[::-1]
            for line in cpuinfo:
                if line.startswith('processor'):
                    result['SYSINFO']['cpuinfo']['cpunum'] = int(line.strip().split(':')[1].strip())+1
                    break
                elif line.startswith('model name'):
                    result['SYSINFO']['cpuinfo']['model name'] = line.strip().split(':')[1].strip()
        result["summary"] += "CPU信息:\n"
        result["summary"] += "Numa node:%s     CPU数量:%s\nCPU model:%s\n"%(
            result['SYSINFO']['cpuinfo']['numa'],
            result['SYSINFO']['cpuinfo']['cpunum'],
            result['SYSINFO']['cpuinfo']['model name'])
        result['SYSINFO']['meminfo'] = {}
        meminfo = get_fs_value(cache_data, "/proc/meminfo")
        if len(meminfo) > 0:
            meminfo = meminfo.splitlines()
            for line in meminfo:
                if line.startswith('MemTotal:'):
                    result['SYSINFO']['meminfo']['MemTotal'] = line.strip().split(':')[1].strip()
                elif line.startswith('MemFree:'):
                    result['SYSINFO']['meminfo']['MemFree'] = line.strip().split(':')[1].strip()
                elif line.startswith('MemAvailable:'):
                    result['SYSINFO']['meminfo']['MemAvailable'] = line.strip().split(':')[1].strip()
                elif line.startswith('Cached:'):
                    result['SYSINFO']['meminfo']['Cached'] = line.strip().split(':')[1].strip()
                elif line.startswith('Slab:'):
                    result['SYSINFO']['meminfo']['Slab'] = line.strip().split(':')[1].strip()
                elif line.startswith('SReclaimable:'):
                    result['SYSINFO']['meminfo']['SReclaimable'] = line.strip().split(':')[1].strip()
                elif line.startswith('SUnreclaim:'):
                    result['SYSINFO']['meminfo']['SUnreclaim'] = line.strip().split(':')[1].strip()
                elif line.startswith('Shmem:'):
                    result['SYSINFO']['meminfo']['Shmem'] = line.strip().split(':')[1].strip()
                elif line.startswith('AnonHugePages:'):
                    result['SYSINFO']['meminfo']['AnonHugePages'] = line.strip().split(':')[1].strip()
                elif line.startswith('AnonPages:'):
                    result['SYSINFO']['meminfo']['AnonPages'] = line.strip().split(':')[1].strip()
                elif line.startswith('Mlocked:'):
                    result['SYSINFO']['meminfo']['Mlocked'] = line.strip().split(':')[1].strip()
        result["summary"] += "内存信息:\n"
        result["summary"] += "Total:%s   Free:%s   Available:%s\nSlab:%s   SUnreclaim:%s\n"%(
            result['SYSINFO']['meminfo']['MemTotal'],result['SYSINFO']['meminfo']['MemFree'],
            result['SYSINFO']['meminfo']['MemAvailable'],result['SYSINFO']['meminfo']['Slab'],
            result['SYSINFO']['meminfo']['SUnreclaim'])
        result['SYSINFO']['blockinfo'] = {}
        cmd = 'df -h 2>/dev/null'
        blockinfo = get_cmddata(cache_data, cmd)
        if len(blockinfo) > 0:
            blockinfo = blockinfo.splitlines()
            for line in blockinfo:
                if line.startswith('/dev/'):
                    line = line.strip().split()
                    result['SYSINFO']['blockinfo'][line[0]] = {}
                    result['SYSINFO']['blockinfo'][line[0]]['Size'] = line[1]
                    result['SYSINFO']['blockinfo'][line[0]]['Used'] = line[2]

    except Exception as e:
        print( 'get_sysinfo exception:',repr(e))
        traceback.print_exc()
        pass

def check_hardware_err(ret):
    hwret = hwcheck.query("", cache_data)
    ret['fields']['HW']['detail'] = hwret['solution']
    ret['fields']['HW']['summary'] += hwret['solution']['summary']
    ret['fields']['cust']['HW'] = hwret['solution']['cust']
    if len(ret['fields']['HW']['summary']) <= 0:
        ret['fields']['HW']['summary'] = "None\n"

def check_highrisk_issues(ret):
    global run_all
    try:
        issue_mod = "process_engine"
        mod = importlib.import_module(issue_mod)
        ret['fields']['ISSUE']['detail'] = mod.query(1,1,run_all)
        if ret['fields']['ISSUE']['detail']['all_matched'] and 'cust' in ret['fields']['ISSUE']['detail']['all_matched']:
            ret['fields']['cust']['ISSUE'] = ret['fields']['ISSUE']['detail']['all_matched']['cust']
            if len(ret['fields']['cust']['ISSUE']) > 0:
                summary_info={}
                for level in utils.SEVERE_LEVEL:
                    summary_info[level]=[]
                for item in ret['fields']['cust']['ISSUE']:
                    if len(ret['fields']['cust']['ISSUE'][item]['level']) > 0:
                        summary_info[ret['fields']['cust']['ISSUE'][item]['level']].append(ret['fields']['cust']['ISSUE'][item])
                for level in utils.SEVERE_LEVEL:
                    if level in summary_info and len(summary_info[level]) > 0:
                        ret['fields']['ISSUE']['summary'] += "匹配%s级别的已知问题:\n"%(level)
                        for item in summary_info[level]:
                            ret['fields']['ISSUE']['summary'] += ("%s:%s\n"%(item['name'], item['summary']))

    except Exception as e:
        print( 'check_highrisk_issues exception:',repr(e))
        traceback.print_exc()
        pass

def query(sn, data):
    ret = {}
    ret['success'] = 'true'
    ret['status'] = 0
    ret['version'] = "1.1"
    ret['fields'] = {}
    ret['fields']['SYSINFO'] = {}
    ret['fields']['CONFIG'] = {}
    ret['fields']['CONFIG']['PARAM'] = {}
    ret['fields']['CONFIG']['PARAM']['SCHED'] = {}
    ret['fields']['CONFIG']['PARAM']['MEM'] = {}
    ret['fields']['CONFIG']['PARAM']['IO'] = {}
    ret['fields']['CONFIG']['PARAM']['NET'] = {}
    ret['fields']['CONFIG']['PARAM']['MISC'] = {}
    ret['fields']['CONFIG']['HOTFIX'] = {}
    ret['fields']['CONFIG']['summary'] = ""
    ret['fields']['SLI'] = {}
    ret['fields']['SLI']['CRASH'] = {}
    ret['fields']['SLI']['SCHED'] = {}
    ret['fields']['SLI']['MEM'] = {}
    ret['fields']['SLI']['IO'] = {}
    ret['fields']['SLI']['NET'] = {}
    ret['fields']['SLI']['MISC'] = {}
    ret['fields']['SLI']['summary'] = ""
    ret['fields']['LOG'] = {}
    ret['fields']['LOG']['DMESG'] = {}
    ret['fields']['LOG']['SYSLOG'] = {}
    ret['fields']['LOG']['summary'] = ""
    ret['fields']['HW'] = {}
    ret['fields']['HW']['CPU'] = {"total_num":0}
    ret['fields']['HW']['RAM'] = {"total_num":0}
    ret['fields']['HW']['DISK'] = {"total_num":0}
    ret['fields']['HW']['NIC'] = {"total_num":0}
    ret['fields']['HW']['MCE'] = {"total_num":0}
    ret['fields']['HW']['summary'] = ""

    ret['fields']['ISSUE'] = {}
    ret['fields']['ISSUE']['summary'] = ""
    ret['fields']["summary"] = ""

    # level:{"info", "warning", "error", "critical", "fatal"}
    ret['fields']['cust'] = {}
    ret['fields']['cust']['CONFIG'] = {}
    ret['fields']['cust']['ISSUE'] = {}
    ret['fields']['cust']['SLI'] = {}
    ret['fields']['cust']['LOG'] = {}
    ret['fields']['cust']['HW'] = {}

    logger.write("")
    hostname = socket.gethostname()
    ret['fields']['hostname'] = hostname

    # Get sysinfo
    get_sysinfo(ret['fields'])

    if run_issuecheck == 1:
        check_highrisk_issues(ret)
    elif run_logcheck == 1 or run_panic == 1:
        check_log(ret,log_file)
    else:
        # crash check
        check_crash(ret)
        # log check
        check_log(ret,log_file)
        # hardware check
        check_hardware_err(ret)
        # SLI check
        # CPU
        check_cpu_indicator(ret)
        # MEM
        check_mem_indicator(ret)
        # IO
        check_io_indicator(ret)
        # NET
        check_net_indicator(ret)
        # MISC
        check_misc_indicator(ret)
        # config check
        # SCHED
        check_sched_params(ret)
        # MEM
        check_mem_params(ret)
        # IO
        check_io_params(ret)
        # NET
        check_net_params(ret)
        # MISC
        check_misc_params(ret)
        # perf
        #check_perf_params(ret)
        # hotfix
        check_hotfix(ret)
        # high risk issues check
        check_highrisk_issues(ret)

        summary = ""
        if len(ret['fields']['CONFIG']['summary']) >= 0:
            info = "\n1.配置相关异常:\n"
            if len(ret['fields']['CONFIG']['summary']) > 0:
                info += ret['fields']['CONFIG']['summary']
            else:
                info += "None\n"
            summary += info
            del ret['fields']['CONFIG']['summary']
        if len(ret['fields']['SLI']['summary']) >= 0:
            info = "\n2.SLI相关异常:\n"
            if len(ret['fields']['SLI']['summary']) > 0:
                info += ret['fields']['SLI']['summary']
            else:
                info += "None\n"
            summary += info
            del ret['fields']['SLI']['summary']
        if len(ret['fields']['ISSUE']['summary']) >= 0:
            info = "\n3.存在如下已知问题,建议联系内核同学修复:\n"
            if len(ret['fields']['ISSUE']['summary']) > 0:
                info += ret['fields']['ISSUE']['summary']
            else:
                info += "None"
            info += "\n"
            summary += info
            del ret['fields']['ISSUE']['summary']
        if len(ret['fields']['LOG']['summary']) >= 0:
            info = "\n4.日志相关异常:\n"
            if len(ret['fields']['LOG']['summary']) > 0:
                info += ret['fields']['LOG']['summary']
            else:
                info += "None\n"
            summary += info
            del ret['fields']['LOG']['summary']
        if len(ret['fields']['HW']['summary']) >= 0:
            info = "\n5.硬件相关异常:\n"
            if len(ret['fields']['HW']['summary']) > 0:
                info += ret['fields']['HW']['summary']
            else:
                info += "None\n"
            summary += info
            del ret['fields']['HW']['summary']

        if ret['status'] == 0:
            ret['fields']["summary"] += "\n诊断结果:无异常"
        else:
            ret['fields']["summary"] += "\n诊断结果:存在如下异常\n" + summary
        print( ret['fields']["summary"])

    if run_panic == 1:
        summary = ret['fields']['SLI']['CRASH']['detail']
        summary = json.dumps(summary,ensure_ascii=False)
        summary = "\n诊断结果:\n"+summary
        ret['fields']["summary"] = summary
        print( summary)
    elif run_issuecheck == 1:
        summary = ret['fields']['ISSUE']['detail']['all_matched']
        if ret:
            summary = json.dumps(summary,ensure_ascii=False)
            summary = "\n诊断结果:\n已知问题:"+summary
        else:
            summary = "\n诊断结果:未发现已知问题"
        ret['fields']["summary"] = summary
        print( summary)
    elif run_logcheck == 1:
        summary = ret['fields']['LOG']['summary']
        summary = "\n诊断结果:\n"+summary
        ret['fields']["summary"] = summary
        print( summary)

    if len(ret) > 0 and __name__=='__main__':
        result = {"ossre":ret}
        result = json.dumps(result,ensure_ascii=False)
        logger.write(result)
        post_ossre_diag(result)
    return ret

def main():
    sn = ''

    global run_offline
    global run_all
    global run_diag
    global run_issuecheck
    global run_logcheck
    global run_panic
    global run_verbose
    global log_file

    os.environ['run_silent']="1"
    parser = argparse.ArgumentParser()
    parser.add_argument('-o','--offline', action='store_true', help='run in offline, no network available.')
    parser.add_argument('-a','--all', action='store_true', help='run ossre in full and slow  mode.')
    parser.add_argument('-v','--verbose', action='store_true', help='enable debugging log.')
    parser.add_argument('-d','--diag', action='store_true', help='run diag mode to diagnose OS exceptions.')
    parser.add_argument('-l','--log', help='run log parse with specified log file only.')
    parser.add_argument('-p','--panic', action='store_true', help='check panic dmesg.')
    parser.add_argument('-i','--issues', action='store_true', help='check known issues only.')
    args = vars(parser.parse_args())
    if args.get('offline',False) == True:
        run_offline = 1
        os.environ['run_offline']=str(run_offline)
    if args.get('all',False) == True:
        run_all = 1
        os.environ['run_all']=str(run_all)
    if args.get('diag',False) == True:
        run_diag = 1
        os.environ['run_diag']=str(run_diag)
    if args.get('verbose',False) == True:
        run_verbose = 1
        os.environ['run_verbose']=str(run_verbose)
    if args.get('issues',False) == True:
        run_issuecheck = 1
        run_diag = 1
        os.environ['run_diag']=str(run_diag)
    if args.get('log',None) is not None:
        run_logcheck = 1
        log_file = args.get('log',None)
        run_diag = 1
        os.environ['run_diag']=str(run_diag)
    if args.get('panic',False) == True:
        run_panic = 1
        os.environ['run_panic']=str(run_panic)
        run_diag = 1
        os.environ['run_diag']=str(run_diag)

    args, left = parser.parse_known_args()
    sys.argv = sys.argv[:1]+left

    global cache_data
    utils.set_cache_data(cache_data)
    ret = query(sn, cache_data)

def get_config():
    try:
        conf = "%s/%s"%(os.path.dirname(os.path.abspath(__file__)),CONFIG_FILE)
        with open(conf,'r') as fin:
            lines = fin.readlines()
            for line in lines:
                if line.startswith('#'):
                    continue
                idx = line.find('=')
                if idx >= 0:
                    key = line[0:idx].strip()
                    val = line[idx+1:].strip()
                    if key == 'dentry_num':
                        ossre_config['dentry_num'] = int(val)
                    elif key == 'max_cgroup_num':
                        ossre_config['max_cgroup_num'] = int(val)
                    elif key == 'highsys_thresh':
                        ossre_config['highsys_thresh'] = float(val)
                    elif key == 'highio_thresh':
                        ossre_config['highio_thresh'] = float(val)
                    elif key == 'highsoftirq_thresh':
                        ossre_config['highsoftirq_thresh'] = float(val)
                    elif key == 'unreclaim_slab_thresh':
                        ossre_config['unreclaim_slab_thresh'] = int(val)
                    elif key == 'memory_frag_thresh':
                        ossre_config['memory_frag_thresh'] = int(val)
                    elif key == 'direct_reclaim_num':
                        ossre_config['direct_reclaim_num'] = int(val)
                    elif key == 'free_percent_thresh':
                        ossre_config['free_percent_thresh'] = int(val)
                    elif key == 'high_await_thresh':
                        ossre_config['high_await_thresh']= float(val)
                    elif key == 'net_retrans_thresh':
                        ossre_config['net_retrans_thresh'] = float(val)
    except Exception as err:
        print( err)
        print( "read %s error" % CONFIG_FILE)
    if run_verbose == 1:
        print( ossre_config)
if __name__ == "__main__":
    get_config()
    main()
