#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Author: shiyan

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

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
sys.path.append("%s/../rules"%(os.path.dirname(os.path.abspath(__file__))))
import utils
import crash
import collect_data

OOM_BEGIN_KEYWORD = "invoked oom-killer"
OOM_END_KEYWORD = "Killed process"
OOM_END_KEYWORD_4_19 = "reaped process"
OOM_CGROUP_KEYWORD = "Task in /"
OOM_NORMAL_MEM_KEYWORD = "Normal: "
OOM_PID_KEYWORD = "[ pid ]"
WEEK_LIST = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']
MONTH_LIST = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sept','Oct','Nov','Dec']

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

def dmesg_has_time_tag(dmesg):
    try:
        for i in range(5):
            if '[' in dmesg[i]:
                if dmesg[i].split('[')[1].split()[0] in WEEK_LIST:
                    return True
        return False
    except:
        print("dmesg_has_time_tag failed!")

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

def num_to_bignum(ori_num):
    try:
        tmp = int(ori_num)
        tag = ""
        if int(tmp/1024)>0:
            tmp = float(tmp)/1024
            tag = "K"
            if int(tmp/1024)>0:
                tmp = tmp/1024
                tag = "M"
                if int(tmp/1024)>0:
                    tmp = tmp/1024
                    tag = "G"
        else:
            return ori_num
        ret = "%.1f%s"%(tmp, tag)
        return ret
    except:
        ori_num

def oom_time_to_normal_time(oom_time):
    try:
        if len(oom_time) > 0:
            ret_time = ""
            oom_time = oom_time.split()
            oom_time[3]
            ret_time = "%s-%02d-%02d %s"%(oom_time[4],MONTH_LIST.index(oom_time[1])+1,int(oom_time[2]),oom_time[3])
            return ret_time
        else:
            return "unknown"
    except:
        return "unknown"

def time_tsar_to_normal(time):
    try:
        ret_time = "20%s-%s-%s %s"%(time.split('/')[2].split('-')[0], time.split('/')[1], time.split('/')[0], time.split('-')[1])
        #print ret_time
        return ret_time
    except:
        print ("time_tsar_to_oom failed!")
        return time

def check_time_ifclose(time1, time2, mins):
    try:
        year1 = time1.split('-')[0]
        year2 = time2.split('-')[0]
        month1 = time1.split('-')[1]
        month2 = time2.split('-')[1]
        day1 = time1.split('-')[2].split()[0]
        day2 = time2.split('-')[2].split()[0]
        hour1 = time1.split()[1].split(':')[0]
        hour2 = time2.split()[1].split(':')[0]
        minute1 = time1.split()[1].split(':')[1]
        minute2 = time2.split()[1].split(':')[1]

        if year1 != year2 or month1 != month2 or day1 != day2:
            return False

        internal = (int(hour2)*60+int(minute2)) -  (int(hour1)*60+int(minute1))

        if internal >= 0 and internal <= int(mins):
            return True

        return False
    except:
        print ("check_time_ifclose failed!")
        return False

def oomcheck_spectime(time, figure):
    try:
        if 'data' not in figure:
            figure['data'] = {}
            sn = ''
        if 'oom_figure' not in figure['data']:
            oom_scan(sn, figure['data'], 1)

        if time not in figure:
            figure[time] = {}

        if 'result' not in figure[time]:
            figure[time]['result'] = {}

        if len(list(figure[time]['result'])) == 0:
            figure[time]['result']['flag'] = 0
            figure[time]['result']['cause'] = {}
            figure[time]['result']['cause']['none']  = "未确定"
            figure[time]['result']['maybe'] = {}
            figure[time]['result']['maybe'] ['flag'] = 0

        if 'OOM' not in figure[time]:
            figure[time]['OOM'] = {}

        for i in range(len(list(figure['data']['oom_figure']['sub_msg']))):
            time_oom = figure['data']['oom_figure']['sub_msg'][i+1]['time']
            time_spectime = time_tsar_to_normal(time)
            if check_time_ifclose(time_oom, time_spectime, 10):
                figure[time]['result']['flag'] == 1
                figure[time]['result']['cause']['OOM'] = "存在OOM"
                figure[time]['OOM']['time'] = time_oom
                figure[time]['OOM']['summary'] = oom_submsg_analyze(i+1, figure['data']['oom_figure'])
            elif check_time_ifclose(time_oom, time_spectime, 30):
                figure[time]['result']['maybe'] ['flag'] = 1
                figure[time]['result']['maybe']['OOM'] = "存在OOM"
                figure[time]['OOM']['time'] = time_oom
                figure[time]['OOM']['summary'] = oom_submsg_analyze(i+1, figure['data']['oom_figure'])

    except:
        print ("oomcheck_spectime failed!")

def oom_submsg_analyze(num, oom_figure):
    try:
        memory_usage = 0
        memory_limit = 0
        memory_free = 0
        memory_min = 0
        oom_figure['sub_msg'][num]['killed_task_mem'] = 0
        summary = ""
        for line in oom_figure['sub_msg'][num]['oom_msg']:
            #print line
            if "memory: usage" in line:
                oom_figure['sub_msg'][num]['type'] = 'cgroup'
                memory_usage = line.strip().split('memory: usage')[1].split()[0].strip(',')
                memory_limit = line.strip().split('limit')[1].split()[0].strip(',')
            if "Normal free:" in line:
                oom_figure['sub_msg'][num]['type'] = 'host'
                memory_free = line.strip().split('Normal free:')[1].split()[0]
                memory_min = line.strip().split('min:')[1].split()[0]
            if "Killed process" in line:
                anon_rss = line.strip().split('anon-rss:')[1].split()[0].strip(',')
                file_rss = line.strip().split('file-rss:')[1].split()[0].strip(',')
                shmem_rss = line.strip().split('shmem-rss:')[1].split()[0].strip(',')
                oom_figure['sub_msg'][num]['killed_task_mem'] = (
                        int(bignum_to_num(anon_rss)) + int(bignum_to_num(file_rss)) + int(bignum_to_num(shmem_rss)))
        if oom_figure['sub_msg'][num]['type'] == 'cgroup':
            if int(bignum_to_num(memory_usage)) > int(bignum_to_num(memory_limit))*4/5:
                summary += "cgroup内存不足，建议增加内存或迁移部分业务进程，当前usage:%s, limit:%s\n"%(
                        num_to_bignum(bignum_to_num(memory_usage)),num_to_bignum(bignum_to_num(memory_limit)))
            if oom_figure['sub_msg'][num]['killed_task_mem'] > int(bignum_to_num(memory_usage))*2/3:
                summary += "进程%s占用内存%s,超过cgroup总usage(%s)的2/3\n"%(
                        oom_figure['sub_msg'][num]['task_name'],num_to_bignum(oom_figure['sub_msg'][num]['killed_task_mem']),num_to_bignum(bignum_to_num(memory_usage)))
        elif oom_figure['sub_msg'][num]['type'] == 'host':
            if int(bignum_to_num(memory_min)) > int(bignum_to_num(memory_free))*4/5:
                summary += "主机内存不足，当前free内存:%s, min水线:%s\n"%(memory_free,memory_min)
            if oom_figure['sub_msg'][num]['killed_task_mem'] > int(bignum_to_num('10g')):
                summary += "进程%s占用内存过大：%s\n"%(oom_figure['sub_msg'][num]['task_name'],num_to_bignum(oom_figure['sub_msg'][num]['killed_task_mem']))

        oom_figure['sub_msg'][num]['summary'] = summary
        return summary


    except:
        print ("oom_submsg_analyze failed!")
        return ""

def oom_msg_analyze(dmesgs, oom_figure):
    try:
        OOM_END_KEYWORD_real = OOM_END_KEYWORD
        time_flag = 0
        if OOM_BEGIN_KEYWORD not in dmesgs:
            return
        dmesg = dmesgs.splitlines()
        if dmesg_has_time_tag(dmesg):
            time_flag = 1
        oom_getting = 0
        for line in dmesg:
            line = line.strip()
            if len(line) > 0 and OOM_BEGIN_KEYWORD in line:
                oom_figure['oom_total_num'] += 1
                oom_getting = 1
                oom_figure['sub_msg'][oom_figure['oom_total_num']] = {}
                oom_figure['sub_msg'][oom_figure['oom_total_num']]['oom_msg'] = []
                if time_flag:
                    oom_figure['sub_msg'][oom_figure['oom_total_num']]['time'] = oom_time_to_normal_time(line.split('[')[1].split(']')[0])
                    oom_figure['time'].append(oom_figure['sub_msg'][oom_figure['oom_total_num']]['time'])
            if oom_getting == 1:
                oom_figure['sub_msg'][oom_figure['oom_total_num']]['oom_msg'].append(line)
                if OOM_END_KEYWORD in line or OOM_END_KEYWORD_4_19 in line:
                    if OOM_END_KEYWORD_4_19 in line:
                        OOM_END_KEYWORD_real = OOM_END_KEYWORD_4_19
                    if OOM_END_KEYWORD in line:
                        OOM_END_KEYWORD_real = OOM_END_KEYWORD
                    oom_getting = 0
                    task_name = line.split(OOM_END_KEYWORD_real)[1].split()[1].strip(',')
                    oom_figure['sub_msg'][oom_figure['oom_total_num']]['task_name'] = task_name
                    if task_name not in oom_figure['task']:
                        oom_figure['task'][task_name] = 1
                    else:
                        oom_figure['task'][task_name] += 1
                    
                if OOM_CGROUP_KEYWORD in line:
                    cgroup_name = line.split('Task in')[1].split()[0]
                    oom_figure['sub_msg'][oom_figure['oom_total_num']]['cgroup_name'] = cgroup_name
                    #print cgroup_name
                    if cgroup_name not in oom_figure['cgroup']:
                        oom_figure['cgroup'][cgroup_name] = 1
                    else:
                        oom_figure['cgroup'][cgroup_name] += 1

    except:
        import traceback
        traceback.print_exc()
        print( "oom_msg_analyze failed!!")

def oom_scan(sn, data, mode):
    try:
        if mode != 1 and mode != 2 and mode != 3:
            print( "Wrong mode! 1: light mode; 2: heavy mode\n")
            return

        oom_figure = {}
        oom_figure['summary'] = ""
        oom_figure['oom_total_num'] = 0
        oom_figure['cgroup'] = {}
        oom_figure['task'] = {}
        oom_figure['sub_msg'] = {}
        oom_figure['last_time'] = {}
        oom_figure['time'] = []

        if 'dmesg' not in data:
            cmd = 'dmesg -T 2>/dev/null'
            output = os.popen(cmd)
            dmesgs = output.read().strip()
            output.close()
            data['dmesg'] = dmesgs
        else:
            dmesgs = data['dmesg']
        if OOM_BEGIN_KEYWORD in dmesgs:
            oom_msg_analyze(dmesgs, oom_figure)

            if mode == 2:
                oom_figure['summary'] += "Time                            Killed process            Cgroup\n"
                for i in range(len(list(oom_figure['sub_msg']))):
                    oom_figure['summary'] += ("%-30s %-25s %s\n"%(
                        oom_figure['sub_msg'][i+1]['time'],oom_figure['sub_msg'][i+1]['task_name'],oom_figure['sub_msg'][i+1]['cgroup_name']))
                oom_figure['summary'] += "\nSummary:\n"

            if mode == 3:
                oom_figure['summary'] += "该机器共发生oom %s 次！\n"%oom_figure['oom_total_num']

            num = 0
            sorted_tasks = sorted(oom_figure['task'].items(), key = lambda kv:(kv[1], kv[0]), reverse=True)
            sorted_cgroups = sorted(oom_figure['cgroup'].items(), key = lambda kv:(kv[1], kv[0]), reverse=True)

            if mode == 1 or mode == 3:
                if len(list(sorted_cgroups)) > 3:
                    oom_figure['summary'] += "cgroup发生oom次数TOP3:\n"
            for i in range(len(list(sorted_cgroups))):
                oom_figure['summary'] += ("cgroup:%s 发生oom的次数：%s\n"%(sorted_cgroups[i][0], sorted_cgroups[i][1]))
                if mode == 1:
                    num += 1
                    if num >= 3:
                        break
            num = 0
            if mode == 1 or mode == 3:
                if len(list(sorted_tasks)) > 3:
                    oom_figure['summary'] += "进程被kill次数TOP3:\n"
            for i in range(len(list(sorted_tasks))):
                oom_figure['summary'] += ("进程%s 被kill的次数：%s\n"%(sorted_tasks[i][0], sorted_tasks[i][1]))
                if mode == 1 or mode == 3:
                    num += 1
                    if num >= 3:
                        break

            if mode == 1 or mode == 3:
                num = 0
                oom_num = len(oom_figure['time'])
                if oom_num > 0:
                    oom_figure['summary'] += ("最近发生oom的时间点：\n")
                    for i in range(oom_num):
                        oom_figure['summary'] += ("%s\n"%oom_figure['time'][oom_num - i - 1])
                        num += 1
                        if num >= 3:
                            break

            if sorted_cgroups[0][1] > 10:
                oom_num = oom_figure['oom_total_num']
                for i in range(oom_num):
                    if sorted_cgroups[0][0] == oom_figure['sub_msg'][oom_num - i - 1]['cgroup_name']:
                        summary = oom_submsg_analyze(oom_num - i - 1, oom_figure)
                        if len(summary) > 0:
                            oom_figure['summary'] += "最频繁oom的cgroup达到%s次：%s\n具体分析：\n"%(sorted_cgroups[0][1],sorted_cgroups[0][0])
                            oom_figure['summary'] += summary
                        break
            if sorted_tasks[0][1] > 10:
                oom_num = oom_figure['oom_total_num']
                anon_rss = []
                file_rss = []
                shmem_rss = []
                total = []
                dmesg = dmesgs.splitlines()
                for line in dmesg:
                    if "Killed process" in line and sorted_tasks[0][0] in line:
                        anon_m = line.strip().split('anon-rss:')[1].split()[0].strip(',')
                        anon_m = int(bignum_to_num(anon_m))
                        anon_rss.append(anon_m)
                        file_m = line.strip().split('file-rss:')[1].split()[0].strip(',')
                        file_m = int(bignum_to_num(file_m))
                        file_rss.append(file_m)
                        shmem_m = line.strip().split('shmem-rss:')[1].split()[0].strip(',')
                        shmem_m = int(bignum_to_num(shmem_m))
                        shmem_rss.append(shmem_m)
                        total_m = anon_m + file_m + shmem_m
                        total.append(total_m)
                anon_avg = sum(anon_rss)/len(anon_rss)
                file_avg = sum(file_rss)/len(file_rss)
                shmem_avg = sum(shmem_rss)/len(shmem_rss)
                total_avg = sum(total)/len(total)
                total_max = max(total)
                main_cost = "unknown"
                if anon_avg > total_avg/2:
                    main_cost = "anon_rss"
                elif file_avg > total_avg/2:
                    main_cost = "file_rss"
                elif shmem_avg > total_avg/2:
                    main_cost = "shmem_rss"
                oom_figure['summary'] += "进程%s因oom被kill达%s次，被kill时占用内存最高达%s，平均%s，主要消耗在%s\n"%(
                    sorted_tasks[0][0], sorted_tasks[0][1], num_to_bignum(total_max), num_to_bignum(total_avg), main_cost)

            if mode == 1 :
                if oom_figure['oom_total_num'] > 0:
                    oom_figure['summary'] += "更多oom分析请在机器执行：\nsudo python /var/lib/ossre/tools/oomcheck.py\n"

        data['oom_figure'] = oom_figure

        if mode == 3:
            oom_ret = {}
            oom_ret["has_oom"] = 0
            oom_ret["summary"] = oom_figure['summary']
            oom_ret["submsg"] = {}
            oom_ret["oom_total_num"] = oom_figure['oom_total_num']
            l = len(list(oom_figure['sub_msg']))
            if l > 0:
                oom_ret["has_oom"] = 1
            for i in range(len(list(oom_figure['sub_msg']))):
                if i >= 10:
                    break
                oom_submsg_analyze(l-i,oom_figure)
                oom_ret["submsg"][l-i] = {}
                oom_ret["submsg"][l-i]["summary"] = oom_figure['sub_msg'][l-i]['summary']
                oom_ret["submsg"][l-i]["ori"] = {}
                oom_ret["submsg"][l-i]["ori"]['time'] = oom_figure['sub_msg'][l-i]['time']
                oom_ret["submsg"][l-i]["ori"]['task_name'] = oom_figure['sub_msg'][l-i]['task_name']
                oom_ret["submsg"][l-i]["ori"]['cgroup_name'] = oom_figure['sub_msg'][l-i]['cgroup_name']
            f = open("/tmp/oomcheck.log", "w+")
            f.write(json.dumps(oom_ret,ensure_ascii=False))
            f.close()

        return oom_figure['summary']

    except:
        import traceback
        traceback.print_exc()
        print( "oom_scan failed!")
        data['oom_figure'] = oom_figure
        if mode == 3:
            if len(oom_ret) <= 0:
                oom_ret = {}
                oom_ret["has_oom"] = 0
            f = open("/tmp/oomcheck.log", "w+")
            f.write(json.dumps(oom_ret,ensure_ascii=False))
            f.close()
        return oom_figure['summary']

def main():
    sn = ''
    data = {}

    print(oom_scan(sn, data, 2))
    if data['oom_figure']['oom_total_num'] > 0:
        oom_figure = data['oom_figure']
        yorn = utils.get_input_str("\n是否进一步分析oom，请输入y/n\n")
        if yorn == 'y':
            print ("NO.    Time                           Killed process            Cgroup")
            l = len(list(oom_figure['sub_msg']))
            #print l
            for i in range(len(list(oom_figure['sub_msg']))):
                print ("%-6s %-30s %-25s %s"%(i+1,
                    #oom_figure['sub_msg'][i+1]['time'],oom_figure['sub_msg'][i+1]['task_name'],oom_figure['sub_msg'][i+1]['cgroup_name']))
                    oom_figure['sub_msg'][l-i]['time'],oom_figure['sub_msg'][l-i]['task_name'],oom_figure['sub_msg'][l-i]['cgroup_name']))
            num = utils.get_input_int("\n请选择具体要分析的oom编号(NO.)\n")
            try:
                if num <= oom_figure['oom_total_num'] and num >= 1:
                    #print(oom_submsg_analyze(num,oom_figure))
                    print(oom_submsg_analyze(l-num+1,oom_figure))
                else:
                    print ("输入错误，退出oom诊断！\n")
            except:
                print ("输入错误，退出oom诊断！\n")
        else:
            print ("退出oom诊断\n")


if __name__ == "__main__":
    sn = ''
    data = {}
    if os.path.isfile("/tmp/oomcheck.log"):
        cmd = 'echo "" > /tmp/oomcheck.log'
        output = os.popen(cmd)
        #a = output.read()
        output.close()
        print "/tmp/oomcheck.log exist"
    else:
        print "/tmp/oomcheck.log not exist"
    oom_scan(sn, data, 3)
    main()
