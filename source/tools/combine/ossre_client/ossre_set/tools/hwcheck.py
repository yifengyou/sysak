# -*- coding: utf-8 -*-
# @Author: zhilan

import sys, os, socket
import time,datetime
import json, base64, hashlib, re
import threading
import sched
import subprocess
import sqlite3
import traceback
import zlib
if sys.version[0] == '2':
    from sets import Set as set

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
sys.path.append("%s/../rules/"%(os.path.dirname(os.path.abspath(__file__))))
sys.path.append("%s/../tools/"%(os.path.dirname(os.path.abspath(__file__))))
import cust_const
import collect_data
import crash
import utils
import multiprocessing
import re

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

run_diag=0
run_verbose = 0

#reference: drivers/scsi/constants.c
#reference: drivers/scsi/pmcraid.h
DISK_HARDWARE_ERR_KEYWORD = ['Recovered Error, soft media error, sector reassignment suggested',
    'Recovered Error, failure prediction threshold exceeded',
    'Recovered Error, soft Cache Card Battery error threshold',
    'Recovered Error, soft Cache Card Battery error threshold',
    'Not Ready, IOA Reset Required',
    'Not Readyr IOA microcode download required',
    'Medium Error, data unreadable, reassignment suggested',
    'Medium Error',
    'Data Protect',
    'Read retries exhausted',
    'Error too long to correct',
    'Sense Key : Hardware Error',
    'Multiple read errors']

# HW errors
MCE_ERR="Machine Check Event"
SENDING_NMI = "Sending NMI"
NMI_BACKTRACE = 'NMI backtrace for cpu '

def check_kern(ret,data):
    kern = ""
    if 'kern' not in data:
        if os.path.exists("/var/log/kern"):
            cmd = 'cat /var/log/kern | tail -n 10000 2>/dev/null'
            output = os.popen(cmd)
            kern = output.read().strip()
            output.close()
            data['kern'] = kern
        else:
            data['kern'] = ""
    else:
        kern = data['kern']
    if len(kern) <= 0:
        return

    if kern.find(MCE_ERR) >= 0:
       if len(ret['solution']['MCE']['detail']) <= 0:
           ret['solution']['summary'] +=  "该机器存在mce错误\n"
       ret['solution']['MCE']['detail'] += "该机器/var/log/kern存在硬件错误日志\n"

def check_mce(ret,data):
    ret['solution']['MCE'] = {}
    ret['solution']['MCE']['detail'] = ""
    # Need to parse mce log
    if os.path.exists("/var/log/mcelog"):
        cmd = 'cat /var/log/mcelog 2>/dev/null'
        mcedata = collect_data.get_cmddata("",data, cmd)
        if len(mcedata) > 0 and not mcedata.startswith("cat:"):
            ret['solution']['summary'] +=  "该机器存在mce错误\n"
            ret['solution']['MCE']['detail'] += "该机器mcelog存在硬件错误日志\n"
            ret['solution']['cust']['MCE'] = {}
            ret['solution']['cust']['MCE']['category'] = cust_const.MCE['category']
            ret['solution']['cust']['MCE']['level'] = cust_const.MCE['level']
            ret['solution']['cust']['MCE']['name'] = cust_const.MCE['name']
            ret['solution']['cust']['MCE']['desc'] = cust_const.MCE['desc']
            ret['solution']['cust']['MCE']['solution'] = cust_const.MCE['solution']
            ret['solution']['cust']['MCE']['summary'] = cust_const.MCE['summary_format']


def check_disk_err(ret,data):
    dmesg = collect_data.get_dmesg("",data)
    if len(dmesg):
        # check disk error
        # TBD: extract disk number
        for word in DISK_HARDWARE_ERR_KEYWORD:
            if dmesg.find(word) > 0:
                ret['solution']['summary'] +=  "该机器存在硬盘硬件错误,建议硬件检修\n"
                ret['solution']['cust']['diskerr'] = {}
                ret['solution']['cust']['diskerr']['category'] = cust_const.diskerr['category']
                ret['solution']['cust']['diskerr']['level'] = cust_const.diskerr['level']
                ret['solution']['cust']['diskerr']['name'] = cust_const.diskerr['name']
                ret['solution']['cust']['diskerr']['desc'] = cust_const.diskerr['desc']
                ret['solution']['cust']['diskerr']['solution'] = cust_const.diskerr['solution']
                ret['solution']['cust']['diskerr']['summary'] = cust_const.diskerr['summary_format']
                break
        if 'diskerr' not in ret['solution']['cust']:
            if dmesg.find('Buffer I/O error on') >= 0 and dmesg.find('sub_code(0x0303)') >= 0:
                ret['solution']['cust']['diskerr'] = {}
                ret['solution']['cust']['diskerr']['category'] = cust_const.diskerr['category']
                ret['solution']['cust']['diskerr']['level'] = cust_const.diskerr['level']
                ret['solution']['cust']['diskerr']['name'] = cust_const.diskerr['name']
                ret['solution']['cust']['diskerr']['desc'] = cust_const.diskerr['desc']
                ret['solution']['cust']['diskerr']['solution'] = cust_const.diskerr['solution']
                ret['solution']['cust']['diskerr']['summary'] = cust_const.diskerr['summary_format']

        if 'diskerr' not in ret['solution']['cust']:
            dmesglist = dmesg.splitlines()
            lblocks = {}
            sumlb = 0
            for line in dmesglist:
                if line.find('EXT4-fs warning') >=0 or line.find('EXT4-fs error') >=0 :
                    if line.find('lblock') >=0 and line.find('error -5') >= 0:
                        gp = re.search('.*lblock (\d*):.*',line)
                        if gp != None:
                            lblock = gp.group(1)
                            sumlb += 1
                            if lblock not in lblocks:
                                lblocks[lblock] = 1
                            else:
                                lblocks[lblock] += 1
            if len(lblocks) < 5 and sumlb > 50:
                ret['solution']['cust']['diskerr'] = {}
                ret['solution']['cust']['diskerr']['category'] = cust_const.diskerr['category']
                ret['solution']['cust']['diskerr']['level'] = cust_const.diskerr['level']
                ret['solution']['cust']['diskerr']['name'] = cust_const.diskerr['name']
                ret['solution']['cust']['diskerr']['desc'] = cust_const.diskerr['desc']
                ret['solution']['cust']['diskerr']['solution'] = cust_const.diskerr['solution']
                ret['solution']['cust']['diskerr']['summary'] = cust_const.diskerr['summary_format']

def check_nmi(ret,data):
    dmesg = collect_data.get_dmesg("",data)
    exclude_cpu = -1
    backtrace_cpu = []

    if len(dmesg):
        idx1 = dmesg.find(SENDING_NMI)
        if idx1 >= 0:
            cpunum = multiprocessing.cpu_count()
            msg = dmesg.splitlines()
            for line in msg:
                gp = re.search('.*NMI backtrace for cpu (\d*).*',line)
                if gp != None:
                    cpu = int(gp.group(1))
                    backtrace_cpu.append(cpu)
        
            result_cpu = [] 
            for i in range(0,cpunum):
                if i == exclude_cpu:
                    continue
                if i not in backtrace_cpu:
                    result_cpu.append(i)
            if len(result_cpu) != 0 and len(result_cpu) < 4:
                ret['solution']['summary'] +=  "该机器存在CPU不响应NMI中断的情况,建议硬件检修\n"
                ret['solution']['cust']['nmi'] = {}
                ret['solution']['cust']['nmi']['category'] = cust_const.nmi_backtrace['category']
                ret['solution']['cust']['nmi']['level'] = cust_const.nmi_backtrace['level']
                ret['solution']['cust']['nmi']['name'] = cust_const.nmi_backtrace['name']
                ret['solution']['cust']['nmi']['desc'] = cust_const.nmi_backtrace['desc']
                ret['solution']['cust']['nmi']['solution'] = cust_const.nmi_backtrace['solution']
                ret['solution']['cust']['nmi']['summary'] = cust_const.nmi_backtrace['summary_format'] % result_cpu

def check_microcode(ret,data):
    cmd = "lscpu"
    lscpu = collect_data.get_cmddata("",data, cmd)

    if lscpu.find("Hypervisor vendor") >= 0:
        return
    cmd = 'cat /proc/cpuinfo'
    cpuinfo = collect_data.get_cmddata("",data, cmd)

    if len(cpuinfo):
        idx1 = cpuinfo.find('model name')
        if idx1 < 0:
            return
        try:
            gp = re.search('model name *: *(.*) .*GHz',cpuinfo)
            if gp == None:
                return
            model_name = gp.group(1)

            idx2 = cpuinfo.find('microcode')
            if idx2 < 0:
                return
            gp = re.search('microcode *: *0x(\S*)',cpuinfo)
            if gp == None:
                return
            mcode_ver = gp.group(1)
            idx3 = mcode.rfind('0',0)
            if idx3 != -1 and idx3 != 0 and idx3 != len(mcode_ver)-1 :
                mcode_ver = mcode_ber[idx3+1:]

            if (model_name.find('Intel(R) Xeon(R) Platinum 8163') >= 0 and mcode_ver < '65') or (model_name.find('Intel(R) Xeon(R) Platinum 8269CY') >= 0 and mcode_ver < '2c'):
                ret['solution']['summary'] +=  "该机器微码版本过低可能会造成虚拟机异常page faults，建议升级微码版本\n"
                ret['solution']['cust']['nmi'] = {}
                ret['solution']['cust']['nmi']['category'] = cust_const.microcode['category']
                ret['solution']['cust']['nmi']['level'] = cust_const.microcode['level']
                ret['solution']['cust']['nmi']['name'] = cust_const.microcode['name']
                ret['solution']['cust']['nmi']['desc'] = cust_const.microcode['desc']
                ret['solution']['cust']['nmi']['solution'] = cust_const.microcode['solution']
                ret['solution']['cust']['nmi']['summary'] = cust_const.microcode['summary_format']
        except:
            pass

def query(sn,data):
    ret = {}
    ret['return'] = False
    ret['solution'] = {}
    ret['solution']['summary'] = ""
    ret['solution']['MCE'] = {}
    ret['solution']['cust'] = {}

    global run_diag
    global run_verbose
    run_diag = os.environ.get('run_diag')
    if run_diag is None:
        run_diag = 0
    else:
        run_diag = int(run_diag)
    run_verbose = os.environ.get('run_verbose')
    if run_verbose is None:
        run_verbose = 0
    else:
        run_verbose = int(run_verbose)

    check_mce(ret,data)
    check_disk_err(ret,data)
    check_kern(ret,data)
    check_nmi(ret,data)
    check_microcode(ret,data)

    if len(ret['solution']['summary']) > 0:
        ret['return'] = True
    if run_verbose:
        print(ret)

    return ret

def main():
    sn = ''
    data = {}

    if os.path.isfile("/tmp/hwcheck.log"):
        cmd = 'echo "" > /tmp/hwcheck.log'
        output = os.popen(cmd)
        output.close()
        print "/tmp/hwcheck.log exist"
    else:
        print "/tmp/hwcheck.log not exist"

    ret = query(sn, data)
    if ret['return']:
        result = {os.path.basename(__file__)[:-3]:ret['solution']}
        result = json.dumps(result,ensure_ascii=False)
        print(result)

        f = open("/tmp/hwcheck.log", "w+")
        f.write(result)
        f.close()

        utils.post_ossre_diag(result)

if __name__ == "__main__":
    main()
