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
import crash
import collect_data

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

CGROUP_NUM_ISSUE = ['SCHED_1010.py']

def num_check():
    sn = ''
    data = {}
    summary = ''
    rets = {}
    rets['issue_result'] = {}
    ret = {}
    ret['return'] = False
    ret['solution'] = {}
    all_matched = {}

    try:
        cgroup_msg = {}
        cmd = "cat /proc/cgroups 2>/dev/null"
        cgproc = collect_data.get_cmddata(sn, data, cmd).splitlines()
        for line in cgproc:
            if 'num_cgroups' not in line:
                item = line.split()
                if int(item[2]) >= 1000:
                    cgroup_msg[item[0]] = {}
                    cgroup_msg[item[0]]['hierarchy'] = int(item[1])
                    cgroup_msg[item[0]]['num_cgroups'] = int(item[2])

        if len(list(cgroup_msg)) > 0:
            for item in cgroup_msg:
                summary += "cgroup子系统:%s 数量:%s 层级:%s\n"%(item,cgroup_msg[item]['num_cgroups'],cgroup_msg[item]['hierarchy'])
            for subdir, dirs, files in os.walk("%s/../rules"%(os.path.dirname(os.path.abspath(__file__)))):
                for file in files:
                    filepath = subdir + os.sep + file
                    if os.path.isfile(filepath):
                        if file.endswith('.py') and file in CGROUP_NUM_ISSUE:
                            rule_mod = file[:-3]
                            try:
                                mod = importlib.import_module(rule_mod)
                                ret = mod.query(sn, data)
                                rets['issue_result'][rule_mod] = {}
                                rets['issue_result'][rule_mod] = ret
                                if ret['return']:
                                    if all_matched.get('online') is None:
                                        all_matched['online'] = {}
                                    if all_matched['online'].get(file) is None:
                                        all_matched['online'][file] = []
                                    all_matched['online'][file].append(ret['solution'])
                            except Exception as e:
                                print( '%s Exception!'%(mod),e)
                                pass
            if len(list(all_matched)) > 0:
                for i in all_matched:
                    summary += "%s\n"%(json.dumps(all_matched[i],ensure_ascii=False))

            dockerids = collect_data.get_dockerids(sn, data)
            if len(dockerids) >= 1000:
                summary += "该主机容器数量过多:%s\n"%len(dockerids)

        return summary
    except:
        print( "num_check failed!")
        pass

def directreclaim_check():
    sn = ''
    data = {}
    summary = ''
    cg_stall = 0
    allocstall = 0
    try:
        cgstat = {}
        cmd = "free -b"
        mem = collect_data.get_cmddata(sn, data, cmd).splitlines()
        for line in mem:
            if 'Mem' in line:
                total_mem = int(line.split()[1])
                free_mem = int(line.split()[3])
                break
        cmd = "cat /sys/fs/cgroup/memory/memory.stat 2>/dev/null"
        cgmstat = collect_data.get_cmddata(sn, data, cmd).splitlines()
        for line in cgmstat:
            if 'total_allocstall' in line:
                cg_stall = int(line.split()[1])

        cmd = "find /sys/fs/cgroup/memory/ -maxdepth 3 -name memory.stat | grep -v '/sys/fs/cgroup/memory/memory.stat'"
        path = collect_data.get_cmddata(sn, data, cmd).splitlines()

        for line in path:
            cmd = "cat %s  2>/dev/null"%line
            allocstall_line = collect_data.get_cmddata(sn, data, cmd).splitlines()
            if len(allocstall_line) > 0:
                for i in allocstall_line:
                    if 'total_allocstall' in i:
                        allocstall = int(i.split()[1])
                        break
                if allocstall >= 10000 and allocstall >= cg_stall/3:
                    cgstat[line] = {}
                    cgstat[line]['allocstall'] = allocstall
                    cgstat[line]['summary'] = "%s:\n"%line.strip('memory.stat')

                    cmd = "ls %s"%line.strip('memory.stat')
                    files = collect_data.get_cmddata(sn, data, cmd)

                    if 'memory.limit_in_bytes' in files:
                        cmd = "cat %s/memory.limit_in_bytes 2>/dev/null"%line.strip('memory.stat')
                        limit_in_bytes = collect_data.get_cmddata(sn, data, cmd)
                        cgstat[line]['limit_in_bytes'] = int(limit_in_bytes.strip())

                    if 'memory.high_wmark' in files:
                        cmd = "cat %s/memory.high_wmark 2>/dev/null"%line.strip('memory.stat')
                        high_wmark = collect_data.get_cmddata(sn, data, cmd)
                        cgstat[line]['high_wmark'] = int(high_wmark.strip())

                    if 'memory.low_wmark' in files:
                        cmd = "cat %s/memory.low_wmark 2>/dev/null"%line.strip('memory.stat')
                        low_wmark = collect_data.get_cmddata(sn, data, cmd)
                        cgstat[line]['low_wmark'] = int(low_wmark.strip())

                    if 'memory.usage_in_bytes' in files:
                        cmd = "cat %s/memory.usage_in_bytes 2>/dev/null"%line.strip('memory.stat')
                        usage_in_byte = collect_data.get_cmddata(sn, data, cmd)
                        cgstat[line]['usage_in_bytes'] = int(usage_in_byte.strip())

                    if 'memory.reclaim_wmarks' in files:
                        cmd = "cat %s/memory.reclaim_wmarks"%line.strip('memory.stat')
                        reclaim_wmarks = collect_data.get_cmddata(sn, data, cmd)
                        for item in reclaim_wmarks.splitlines():
                            if 'high_wmark' in item:
                                cgstat[line]['high_wmark'] = int(item.split()[1])
                            if 'low_wmark' in item:
                                cgstat[line]['low_wmark'] = int(item.split()[1])
                    #print "cgstat[line]['allocstall']: %s"%cgstat[line]['allocstall']
                    #print "cgstat[line]['limit_in_bytes']: %s"%cgstat[line]['limit_in_bytes']
                    #print "cgstat[line]['high_wmark']: %s"%cgstat[line]['high_wmark']
                    #print "cgstat[line]['low_wmark']: %s"%cgstat[line]['low_wmark']
                    #print "cgstat[line]['usage_in_bytes']: %s"%cgstat[line]['usage_in_bytes']

                    #cgstat[line]['usage'] = cgstat[line]['usage_in_bytes']*100/cgstat[line]['limit_in_bytes']
                    #print "cgstat[line]['usage']: %s%%"%cgstat[line]['usage']
                    cgstat[line]['summary'] += "directreclaim次数:%s, limit_in_bytes:%s, high_wmark:%s\n"%(cgstat[line]['allocstall'],cgstat[line]['limit_in_bytes'],cgstat[line]['high_wmark'])
                    if cgstat[line]['high_wmark'] < cgstat[line]['limit_in_bytes']/3*2 and cgstat[line]['high_wmark'] < total_mem:
                        cgstat[line]['summary'] += "诊断原因：high_wmark设置小于limit的2/3，可以适当调高\n"
        if len(list(cgstat)) > 0:
            path_tmp = []
            for path in cgstat:
                path_tmp.append(path)
            len_i = len(path_tmp)
            for i in range(len_i):
                len_j = len_i - i - 1
                if len_j > 0:
                    for j in range(len_j):
                        if path_tmp[i].strip('memory.stat') in path_tmp[i+j+1].strip('memory.stat'):
                            if cgstat[path_tmp[i+j+1]]['allocstall'] > cgstat[path_tmp[i]]['allocstall']/3*2:
                                del cgstat[path_tmp[i]]
                        if path_tmp[i+j+1].strip('memory.stat') in path_tmp[i].strip('memory.stat'):
                            if cgstat[path_tmp[i]]['allocstall'] > cgstat[path_tmp[i+j+1]]['allocstall']/3*2:
                                del cgstat[path_tmp[i+j+1]]

        if len(list(cgstat)) > 0:
            summary += "频繁directreclaim的cgroup:\n"
            for path in cgstat:
                summary += cgstat[path]['summary']

        dockerids = collect_data.get_dockerids(sn, data)
        if len(dockerids) <= 0:
            return summary
        else:
            if len(dockerids) >= 1000:
                summary += "该主机容器数量过多:%s\n"%len(dockerids)
                return summary
            dkstat = {}
        for dockerid in dockerids:
            cmd = "find /sys/fs/cgroup/memory/ -type d -iname '%s*'"%(dockerid)
            id_path = collect_data.get_cmddata(sn, data, cmd)

            if len(id_path) == 0:
                cmd = "find /sys/fs/cgroup/memory/ -type d -iname 'kangaroo_%s*'"%(dockerid)
                id_path = collect_data.get_cmddata(sn, data, cmd)
                if len(id_path) == 0:
                    continue
            id_path = id_path.splitlines()[0].strip()

            cmd = "cat %s/memory.stat |grep total_allocstall 2>/dev/null"%id_path
            allocstall_line = collect_data.get_cmddata(sn, data, cmd)
            if len(allocstall_line) > 0:
                allocstall = int(allocstall_line.split()[1])
                if allocstall >= 10000 and allocstall >= cg_stall/3:
                    dkstat[dockerid] = {}
                    dkstat[dockerid]['allocstall'] = allocstall
                    dkstat[dockerid]['summary'] = "docker id: %s\n"%dockerid



                    if 'memory.limit_in_bytes' in files:
                        cmd = "cat %s/memory.limit_in_bytes 2>/dev/null"%id_path
                        limit_in_bytes = collect_data.get_cmddata(sn, data, cmd)
                        dkstat[dockerid]['limit_in_bytes'] = int(limit_in_bytes.strip())

                    if 'memory.high_wmark' in files:
                        cmd = "cat %s/memory.high_wmark 2>/dev/null"%id_path
                        high_wmark = collect_data.get_cmddata(sn, data, cmd)
                        dkstat[dockerid]['high_wmark'] = int(high_wmark.strip())

                    if 'memory.low_wmark' in files:
                        cmd = "cat %s/memory.low_wmark 2>/dev/null"%id_path
                        low_wmark = collect_data.get_cmddata(sn, data, cmd)
                        dkstat[dockerid]['low_wmark'] = int(low_wmark.strip())

                    if 'memory.reclaim_wmarks' in files:
                        cmd = "cat %s/memory.reclaim_wmarks"%id_path
                        reclaim_wmarks = collect_data.get_cmddata(sn, data, cmd)
                        for item in reclaim_wmarks.splitlines():
                            if 'high_wmark' in item:
                                dkstat[dockerid]['high_wmark'] = int(item.split()[1])
                            if 'low_wmark' in item:
                                dkstat[dockerid]['low_wmark'] = int(item.split()[1])

                    dkstat[dockerid]['summary'] += "directreclaim次数:%s, limit_in_bytes:%s, high_wmark:%s\n"%(dkstat[dockerid]['allocstall'],dkstat[dockerid]['limit_in_bytes'],dkstat[dockerid]['high_wmark'])
                    if dkstat[dockerid]['high_wmark'] < dkstat[dockerid]['limit_in_bytes']/3*2 and dkstat[dockerid]['high_wmark'] < total_mem:
                        dkstat[dockerid]['summary'] += "诊断原因：high_wmark设置小于limit的2/3，可以适当调高\n"
        if len(list(dkstat)) > 0:
            summary += "存在频繁directreclaim的容器:\n"
            for path in dkstat:
                summary += dkstat[path]['summary']
        if len(list(cgstat)) > 0 or len(list(dkstat)) > 0:
            if free_mem < total_mem/8:
                summary += "诊断原因：主机内存不足, total:%sGB, free:%sGB(%s%%)\n"%(total_mem/1024/1024/1024, free_mem/1024/1024/1024, free_mem*100/total_mem)
        return summary

    except:
        print( "directreclaim_check failed!")
        pass

def main():
    print( directreclaim_check())
    print( num_check())

if __name__ == "__main__":
    main()
