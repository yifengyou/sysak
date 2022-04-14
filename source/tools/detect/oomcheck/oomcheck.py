#!/usr/bin/python2
# -*- coding: utf-8 -*-
# @Author: changjun

from subprocess import *
import os, fcntl, re, sys
from time import sleep
import socket
import time,datetime
import json,base64,hashlib,re
import threading
import sched
import importlib
import json
import argparse
import getopt

OOM_REASON_CGROUP = 'Cgroup内存使用量达到上限',
OOM_REASON_PCGROUP = '父Cgroup内存使用量达到上限',
OOM_REASON_HOST = '主机内存不足',
OOM_REASON_MEMLEAK = '主机内存不足,存在内存泄漏',
OOM_REASON_NODEMASK = 'mempolicy配置不合理',
OOM_REASON_NODE = 'CPUSET 的mems值设置不合理',
OOM_REASON_MEMFRAG = '内存碎片化,需要进行内存规整',
OOM_RESAON_SYSRQ = 'sysrq',
OOM_RESAON_OTHER = 'other'


OOM_BEGIN_KEYWORD = "invoked oom-killer"
OOM_END_KEYWORD = "Killed process"
OOM_END_KEYWORD_4_19 = "reaped process"
OOM_CGROUP_KEYWORD = "Task in /"
OOM_NORMAL_MEM_KEYWORD = "Normal: "
OOM_PID_KEYWORD = "[ pid ]"
WEEK_LIST = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']
CWEEK_LIST = ['一','二','三','四','五','六','日']
MONTH_LIST = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
CMONTH_LIST = ['1月','2月','3月','4月','5月','6月','7月','8月','9月','10月','11月','12月']


if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

def set_to_list(setstr):
    setstr = setstr.split(',')
    resset = []
    for line in setstr:
        line = line.strip()
        if line.find('-') >= 0:
            resset.extend([i for i in range(int(line.split('-')[0]), int(line.split('-')[1])+1)])
        else:
            resset.append(int(line))
    return resset

def bignum_to_num(ori_num):
    try:
        ret_num = ori_num
        if 'kB' in ori_num:
            ret_num = str(int(ori_num.rstrip('kB')) * 1024)
        elif 'KB' in ori_num:
            ret_num = str(int(ori_num.rstrip('KB')) * 1024)
        elif 'k' in ori_num:
            ret_num = str(int(ori_num.rstrip('k')) * 1024)
        elif 'K' in ori_num:
            ret_num = str(int(ori_num.rstrip('K')) * 1024)
        if 'M' in ori_num:
            ret_num = str(int(ori_num.rstrip('M')) * 1024*1024)
        if 'G' in ori_num:
            ret_num = str(int(ori_num.rstrip('G')) * 1024*1024*1024)
        if 'm' in ori_num:
            ret_num = str(int(ori_num.rstrip('m')) * 1024*1024)
        if 'g' in ori_num:
            ret_num = str(int(ori_num.rstrip('g')) * 1024*1024*1024)
        return ret_num
    except:
        return ori_num

def oom_get_ts(oom_time):
    if oom_time.find(".") == -1:
        return 0
    return float(oom_time)

def oom_get_ymdh(oom_time):
    if oom_time.find(":") == -1:
        return 0
    oom_time = oom_time.split()
    ret_time = ""
    if oom_time[0] in WEEK_LIST:
        ret_time = "%s-%02d-%02d %s"%(oom_time[4],MONTH_LIST.index(oom_time[1])+1,int(oom_time[2]),oom_time[3])
    elif oom_time[0] in CWEEK_LIST:
        ret_time = "%s-%02d-%02d %s"%(oom_time[4],CMONTH_LIST.index(oom_time[1])+1,int(oom_time[2]),oom_time[3])
    return normal_time2ts(ret_time)

def oom_time_to_normal_time(oom_time):
    if len(oom_time.strip()) == 0:
        return 0
    try:
        if oom_time.find(":") != -1:
            return oom_get_ymdh(oom_time)
        elif oom_time.find(".") != -1:
            return oom_get_ts(oom_time)
    except:
        return 0

def normal_time2ts(oom_time):
    if len(oom_time) < 8:
        return 0
    ts = time.strptime(oom_time, "%Y-%m-%d %H:%M:%S")
    return float(time.mktime(ts))

def oomcheck_get_spectime(time, oom_result):
    try:
        delta = 3153600000
        num = oom_result['oom_total_num']
        for i in range(oom_result['oom_total_num']):
            time_oom = oom_result['sub_msg'][i+1]['time']
            if abs(time - time_oom) <= delta:
                delta  = abs(time - time_oom)
                num = i
        return num + 1
    except Exception as err:
        print ("oomcheck_spectime error {}".format(err))

def oom_is_node_num(line):
    return "hugepages_size=2048" in line

def oom_get_mem_allowed(oom_result, line, num):
    cpuset = line.strip().split("cpuset=")[1].split()[0]
    allowed = line.strip().split("mems_allowed=")[1]
    oom_result['sub_msg'][num]['mems_allowed'] = set_to_list(allowed)
    oom_result['sub_msg'][num]['cpuset'] = cpuset

def oom_is_host_oom(reason):
    return reason == OOM_REASON_HOST

def oom_get_pid(oom_result, line, num):
    pid = line.strip().split("Killed process")[1].strip().split()[0]
    oom_result['sub_msg'][num]['pid'] = pid

def oom_get_task_mem(oom_result, line, num):
    anon_rss = line.strip().split('anon-rss:')[1].split()[0].strip(',')
    file_rss = line.strip().split('file-rss:')[1].split()[0].strip(',')
    shmem_rss = line.strip().split('shmem-rss:')[1].split()[0].strip(',')
    oom_result['sub_msg'][num]['killed_task_mem'] = (
        int(bignum_to_num(anon_rss)) + int(bignum_to_num(file_rss)) + int(bignum_to_num(shmem_rss)))

def oom_get_host_mem(oom_result, line, num):
    oom_result['sub_msg'][num]['reason'] = OOM_REASON_HOST
    memory_free = line.strip().split('Normal free:')[1].split()[0]
    memory_low = line.strip().split('low:')[1].split()[0]
    oom_result['sub_msg'][num]['host_free'] = memory_free
    oom_result['sub_msg'][num]['host_low'] = memory_low

def oom_get_cgroup_mem(oom_result, line, num):
    memory_usage = line.strip().split('memory: usage')[1].split()[0].strip(',')
    memory_limit = line.strip().split('limit')[1].split()[0].strip(',')
    oom_result['sub_msg'][num]['cg_usage'] = memory_usage
    oom_result['sub_msg'][num]['cg_limit'] = memory_limit

def oom_get_cgroup_name(oom_result, line, num):
    is_host = False
    if "limit of host" in line:
        is_host = True
    if is_host == False:
        oom_result['sub_msg'][num]['reason'] = OOM_REASON_CGROUP
    task_list = line.strip().split("Task in")[1].strip().split()
    cgroup = task_list[0]
    pcgroup = task_list[-1]
    if is_host == False and cgroup != pcgroup:
       #cgroup = pcgroup
       oom_result['sub_msg'][num]['reason'] = OOM_REASON_PCGROUP
    oom_result['sub_msg'][num]['cg_name'] = cgroup

def oom_get_order(oom_result, line, num):
    order = int(line.strip().split("order=")[1].split()[0][:-1])
    oom_result['sub_msg'][num]['order'] = order

def oom_get_nodemask(oom_result, line, num):
    nodemask = line.strip().split("nodemask=")[1].split()[0][:-1]
    oom_result['sub_msg'][num]['nodemask'] = set_to_list(nodemask)

def oom_set_node_oom(oom_result, num, node_num):
    task_mem_allow = oom_result['sub_msg'][num]['mems_allowed']
    is_host = oom_is_host_oom(oom_result['sub_msg'][num]['reason'])
    if is_host and len(task_mem_allow) != node_num:
            oom_result['sub_msg'][num]['reason'] = OOM_REASON_NODE

def oom_get_slab_unrecl(oom_result, line, num):
    if "slab_unreclaimable" not in line:
        oom_result['sub_msg'][num]['slab'] = 0
        return True
    slab_str = line.strip().split("slab_unreclaimable:")[1].split()[0]
    if slab_str.endswith('kB'):
        slab = int(slab_str[:-2])
    else:
        slab = int(slab_str)
    oom_result['sub_msg'][num]['slab'] = slab
    return True

def oom_get_total_mem(oom_result, line, num):
    if "pages RAM" not in line:
        oom_result['total_mem'] = 0
        return True
    total = line.strip().split(']')[1].strip().split()[0]
    total = int(total)
    oom_result['total_mem'] = total
    return True

def oom_is_cgroup_oom(cgroup):
    return cgroup == OOM_REASON_PCGROUP or cgroup == OOM_REASON_CGROUP


def oom_costly_order(order):
    return order >=1 and order <=3

def oom_is_memfrag_oom(oom):
    free = oom['host_free']
    low = oom['host_low']
    order = oom['order']
    memfrag = False
    if free > low and oom_costly_order(order):
        memfrag = True
    return memfrag


def oom_is_memleak(oom, oom_result):
    return oom['slab'] > oom_result['total_mem'] * 0.1

def oom_host_output(oom_result, num):
    oom = oom_result['sub_msg'][num]
    reason = oom['reason']
    summary = ''
    if not oom_is_host_oom(reason):
        return summary
    free = int(oom['host_free'][:-2])
    low = int(oom['host_low'][:-2])
    is_low = False
    if free * 0.9  < low:
        is_low = True
    if oom_result['node_num'] != len(oom['mems_allowed']) and is_low:
        oom['reason'] = OOM_REASON_NODE
        summary += "Node总内存:%d\n"%(oom_result['node_num'])
        summary += "Cpuset名:%s,"%(oom['cpuset'])
        summary += "Cpuset内存配置:"
        for node in oom['mems_allowed']:
            summary +="%s "%(node)
        summary += "\n"
        summary += "Node剩余内存:%s,"%(oom['host_free'])
        summary += "Node low水线:%s\n"%(oom['host_low'])
        return summary
    elif 'nodemask' in oom and len(oom['nodemask']) != oom_result['node_num'] and free > low * 2:
        oom['reason'] = OOM_REASON_NODEMASK
        summary += "Node总内存:%d\n"%(oom_result['node_num'])
        summary += "nodemask内存配置:"
        for node in oom['nodemask']:
            summary +="%s "%(node)
        summary += "\n"
        summary += "Node剩余内存:%s,"%(oom['host_free'])
        summary += "Node low水线:%s\n"%(oom['host_low'])
        return summary
    elif oom_is_memfrag_oom(oom):
        summary += "分配Order:%d\n"%(oom['order'])
        oom['reason'] = OOM_REASON_MEMFRAG
    elif oom_is_memleak(oom, oom_result):
        summary += "SUnreclaim:%d\n"%(oom['slab'])
        oom['reason'] = OOM_REASON_MEMLEAK

    summary += "主机剩余内存:%s,"%(oom['host_free'])
    summary += "主机Low水线:%s\n"%(oom['host_low'])
    return summary

def oom_cgroup_output(oom_result, num):
    summary = ''
    oom = oom_result['sub_msg'][num]
    reason = oom['reason']
    if not oom_is_cgroup_oom(reason):
        return summary
    summary += "cgroup内存使用量:%s,"%(oom['cg_usage'])
    summary += "cgroup内存限制:%s\n"%(oom['cg_limit'])
    return summary

def oom_check_score(oom, oom_result):
    res = oom_result['max']
    if res['pid'] == 0:
        return '\n'
    if int(oom['pid'].strip()) == res['pid']:
        return '\n'
    if res['score'] >= 0:
        return '\n'
    return '，进一步确认进程oom score设置是否合理: %s-%d oom_score_adj:%d rss:%dKB\n'%(res['task'],res['pid'],res['score'],res['rss']*4)

def oom_output_msg(oom_result,num):
    oom = oom_result['sub_msg'][num]
    summary = ''
    #print("oom time = {} spectime = {}".format(oom['time'], oom_result['spectime']))
    task = oom['task_name']
    summary += "Kill进程: %s,Pid:%s\n"%(task[1:-1], oom['pid'])
    summary += "进程Kill次数:%s,进程内存占用量:%sKB\n"%(oom_result['task'][task], oom['killed_task_mem']/1024)
    summary += "进程所属cgroup:%s,"%(oom['cg_name'])
    if oom['cg_name'] in oom_result['cgroup']:
        summary += "cgroup OOM总次数:%s\n"%(oom_result['cgroup'][oom['cg_name']])
    summary += oom_cgroup_output(oom_result, num)
    summary += oom_host_output(oom_result, num)
    summary += "诊断结论:%s"%(oom['reason'])
    summary += oom_check_score(oom, oom_result)
    return summary

def oom_get_max_task(num, oom_result):
    oom = oom_result['sub_msg'][num]
    dump_task = False
    res = oom_result['max']

    for line in oom['oom_msg']:
        if 'rss' in line and 'oom_score_adj' in line and 'name' in line:
            dump_task = True
            continue
        if not dump_task:
            continue
        if "Kill process" in line:
            break

        pid_idx = line.rfind('[')
        last_idx = line.rfind(']')
        if pid_idx == -1 or last_idx == -1:
            continue
        pid = int(line[pid_idx+1:last_idx].strip())
        last_str = line[last_idx+1:].strip()
        last = last_str.split()
        if len(last) < 3:
            continue
        if int(last[3]) < res['rss']:
            continue
        res['rss'] = int(last[3])
        res['score'] = int(last[-2])
        res['task'] = last[-1]
        res['pid'] = pid
    return res

def oom_reason_analyze(num, oom_result):
    try:
        summary = ""
        node_num = 0
        for line in oom_result['sub_msg'][num]['oom_msg']:
            #print line
            if "invoked oom-killer" in line:
                oom_get_order(oom_result, line, num)
                if 'nodemask' in line:
                    oom_get_nodemask(oom_result, line, num)
            elif oom_is_node_num(line):
                node_num += 1
            elif "mems_allowed=" in line:
                oom_get_mem_allowed(oom_result, line, num)
            elif "Task in" in line:
                oom_get_cgroup_name(oom_result, line, num)
            elif "memory: usage" in line:
                oom_get_cgroup_mem(oom_result, line, num)
            elif "Normal free:" in line:
                oom_get_host_mem(oom_result, line, num)
            elif "slab_unreclaimable:" in line:
                oom_get_slab_unrecl(oom_result, line, num)
            elif "pages RAM" in line:
                oom_get_total_mem(oom_result, line, num)
            elif "Killed process" in line:
                oom_get_task_mem(oom_result, line, num)
                oom_get_pid(oom_result, line, num)
        oom_result['node_num'] = node_num
        summary = oom_output_msg(oom_result, num)
        oom_result['sub_msg'][num]['summary'] = summary
        return summary
    except Exception as err:
        print ("oom_reason_analyze err {}\n".format(err))
        return ""

def oom_dmesg_analyze(dmesgs, oom_result):
    try:
        OOM_END_KEYWORD_real = OOM_END_KEYWORD
        if OOM_BEGIN_KEYWORD not in dmesgs:
            return
        dmesg = dmesgs.splitlines()
        oom_getting = 0
        for line in dmesg:
            line = line.strip()
            if len(line) > 0 and OOM_BEGIN_KEYWORD in line:
                oom_result['oom_total_num'] += 1
                oom_getting = 1
                oom_result['sub_msg'][oom_result['oom_total_num']] = {}
                oom_result['sub_msg'][oom_result['oom_total_num']]['oom_msg'] = []
                oom_result['sub_msg'][oom_result['oom_total_num']]['time'] = 0 
                oom_result['sub_msg'][oom_result['oom_total_num']]['cg_name'] = 'unknow'
                if line.find('[') != -1:
                    oom_result['sub_msg'][oom_result['oom_total_num']]['time'] = oom_time_to_normal_time(line.split('[')[1].split(']')[0])
                oom_result['time'].append(oom_result['sub_msg'][oom_result['oom_total_num']]['time'])
            if oom_getting == 1:
                oom_result['sub_msg'][oom_result['oom_total_num']]['oom_msg'].append(line)
                if OOM_END_KEYWORD in line or OOM_END_KEYWORD_4_19 in line:
                    if OOM_END_KEYWORD_4_19 in line:
                        OOM_END_KEYWORD_real = OOM_END_KEYWORD_4_19
                    if OOM_END_KEYWORD in line:
                        OOM_END_KEYWORD_real = OOM_END_KEYWORD
                    oom_getting = 0
                    task_name = line.split(OOM_END_KEYWORD_real)[1].split()[1].strip(',')
                    oom_result['sub_msg'][oom_result['oom_total_num']]['task_name'] = task_name
                    if task_name not in oom_result['task']:
                        oom_result['task'][task_name] = 1
                    else:
                        oom_result['task'][task_name] += 1
                    
                if OOM_CGROUP_KEYWORD in line:
                    cgroup_name = line.split('Task in')[1].split()[0]
                    oom_result['sub_msg'][oom_result['oom_total_num']]['cgroup_name'] = cgroup_name
                    #print cgroup_name
                    if cgroup_name not in oom_result['cgroup']:
                        oom_result['cgroup'][cgroup_name] = 1
                    else:
                        oom_result['cgroup'][cgroup_name] += 1

    except Exception as err:
        import traceback
        traceback.print_exc()
        print( "oom_dmesg_analyze failed {}".format(err))

def oom_read_dmesg(data, mode, filename):
    if mode == 1:
        cmd = 'dmesg -T 2>/dev/null'
        output = os.popen(cmd)
        dmesgs = output.read().strip()
        output.close()
        data['dmesg'] = dmesgs
    elif mode == 2:
       with open(filename, 'r') as f:
           data['dmesg'] = f.read().strip()

def oom_diagnose(sn, data, mode):
    try:
        oom_result = {}
        oom_result['summary'] = ""
        oom_result['oom_total_num'] = 0
        oom_result['cgroup'] = {}
        oom_result['task'] = {}
        oom_result['sub_msg'] = {}
        oom_result['last_time'] = {}
        oom_result['time'] = []
        oom_result['spectime'] = data['spectime']
        oom_result['total_mem'] = 0
        oom_result['slab'] = 0
        oom_result['max'] = {'rss':0,'task':"",'score':0,'pid':0}
        dmesgs = data['dmesg']
        if OOM_BEGIN_KEYWORD in dmesgs:
            oom_dmesg_analyze(dmesgs, oom_result)
            oom_result['summary'] += "主机OOM总次数: %s\n"%oom_result['oom_total_num']

            sorted_tasks = sorted(oom_result['task'].items(), key = lambda kv:(kv[1], kv[0]), reverse=True)
            sorted_cgroups = sorted(oom_result['cgroup'].items(), key = lambda kv:(kv[1], kv[0]), reverse=True)
            last_oom = oom_result["oom_total_num"]
            num = oomcheck_get_spectime(oom_result['spectime'], oom_result)
            if num < 0 or num > last_oom:
                num = last_oom
            res = oom_get_max_task(num, oom_result)
            submsg = oom_reason_analyze(num, oom_result)
            oom_result['summary'] += submsg
        data['oom_result'] = oom_result
        return oom_result['summary']

    except Exception as err:
        import traceback
        traceback.print_exc()
        print( "oom_diagnose failed {}".format(err))
        data['oom_result'] = oom_result
        return oom_result['summary']

#
# mode = 1 for  live mode
# mode = 2 for file mode
def main():
    sn = ''
    data = {}
    data['mode'] = 1
    data['filename'] = ''
    data['spectime'] = int(time.time())
    get_opts(data)
    oom_read_dmesg(data, data['mode'], data['filename'])
    print(oom_diagnose(sn, data, data['mode']))


def usage():
    print(
        """
            -h --help     print the help
            -f --dmesg file
            -l --live mode
            -t --time mode
           for example:
           python oomcheck.py
           python oomcheck.py -t "2021-09-13 15:32:22" 
           python oomcheck.py -t 970665.476522 
           python oomcheck.py -f oom_file.txt
           python oomcheck.py -f oom_file.txt -t 970665.476522
        """
    )

def get_opts(data):
    options,args = getopt.getopt(sys.argv[1:],"hlf:t:",["help","file=","live=","time="])
    for name,value in options:
        if name in ("-h","--help"):
            usage()
            sys.exit(0)
        elif name in ("-f","--file"):
            data['mode'] = 2
            data['filename'] = value
        elif name in ("-l","--live"):
            data['mode'] = 1
        elif name in ("-t","--time"):
            if '-' in value:
                value = normal_time2ts(value)
            data['spectime'] = float(value)

if __name__ == "__main__":
    main()
