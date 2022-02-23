#!/usr/bin/python2
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

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

def get_cmddata(sn, data, cmd, updated=0):
    if updated or cmd not in data:
        data[cmd] = ''
        try:
            output = os.popen(cmd)
            data[cmd] = output.read()
            output.close()
        except:
            print( 'get_cmddata exception!')
            data[cmd] = ''
    return data[cmd]

def get_dockerids(sn, data, updated=0):
    if updated or 'dockerids' not in data:
        data['dockerids'] = []
        if 'dockercmd' not in data:
            cmd = 'which pouch 2>/dev/null'
            output = os.popen(cmd)
            ret = output.read()
            output.close()
            if len(ret) <= 0 or ret.find('which') >= 0:
                cmd = 'which docker 2>/dev/null'
                output = os.popen(cmd)
                ret = output.read()
                if len(ret) <= 0 or ret.find('which') >= 0:
                    data['dockercmd'] = ''
                else:
                    data['dockercmd'] = 'docker'
                output.close()
            else:
                data['dockercmd'] = 'pouch'
        if len(data['dockercmd']) == 0:
            data['dockerids'] = []
            return data['dockerids']
        try:
            cmd = "%s ps -q | awk '{print $1}'"%(data['dockercmd'])
            output = os.popen(cmd)
            ret = output.read()
            output.close()

            ret = ret.split()
            data['dockerids'] = ret
        except:
            print( 'get_dockerids exception!')
            data['dockerids'] = []
    return data['dockerids']

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
        cgproc = get_cmddata(sn, data, cmd).splitlines()
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

            dockerids = get_dockerids(sn, data)
            if len(dockerids) >= 1000:
                summary += "该主机容器数量过多:%s\n"%len(dockerids)

        return summary
    except:
        print( "num_check failed!")
        pass

def main():
    print( num_check())

if __name__ == "__main__":
    main()
