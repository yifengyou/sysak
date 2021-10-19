# -*- coding: utf-8 -*-
# @Author: lichen

import os, socket
import time,datetime
import json, base64, hashlib, re
import crash

def get_live_crash(sn, data, updated=0):
    if 'crash_inst' not in data:
        data['crash_inst'] = None
    if data['crash_inst'] is None or updated:
        if 'vmcore' in data and 'vmlinux' in data:
            data['crash_inst'] = crash.Crash(data['vmcore'], data['vmlinux'])
        else:
            data['crash_inst'] = crash.Crash()
    return data['crash_inst']

def get_vmcore_crash(sn, data, vmcore_path, vmlinux_path, updated=0):
    if 'vmcore' not in data:
        data['vmcore'] = {}
    if vmcore_path not in data['vmcore'] or updated:
        vmcore_crash = crash.Crash(vmcore_path, vmlinux_path)
        data['vmcore'][vmcore_path] = vmcore_crash
    return vmcore_crash

def get_procfs_value(sn, data, proc_path, updated=0):
    if 'proc' not in data:
        data['proc'] = {}
    if updated or proc_path not in data['proc']:
        try:
            cmd = 'cat %s'%proc_path
            output = os.popen(cmd)
            data['proc'][proc_path] = output.read()
            output.close()
        except:
            print( 'get_procfs_value(path %s) exception!'%proc_path)
            data['proc'][proc_path] = ''

    return data['proc'][proc_path] 

def get_sysfs_value(sn, data, sysfs_path, updated=0):
    if 'sysfs' not in data:
        data['sysfs'] = {}
    if updated or sysfs_path not in data['sysfs']:
        try:
            cmd = 'cat %s'%sysfs_path
            output = os.popen(cmd)
            data['sysfs'][sysfs_path] = output.read()
            output.close()
        except:
            print( 'get_sysfs_value(path %s) exception!'%sysfs_path)
            data['sysfs'][sysfs_path] = ''
    return data['sysfs'][sysfs_path]

def get_dmesg(sn, data, updated=0):
    if updated or 'dmesg' not in data:
        try:
            cmd = 'dmesg -T'
            output = os.popen(cmd)
            data['dmesg'] = output.read()
            output.close()
        except:
            print( 'get_dmesg exception!')
            data['dmesg'] = ''
    return data['dmesg']

def get_mcelog(sn, data, updated=0):
    if updated or 'mcelog' not in data:
        try:
            cmd = 'cat /var/log/mcelog 2>/dev/null'
            output = os.popen(cmd)
            data['mcelog'] = output.read()
            output.close()
        except:
            print( 'get_mcelog exception!')
            data['mcelog'] = ''
    return data['mcelog']

def get_meminfo(sn, data, updated=0):
    if updated or 'meminfo' not in data:
        data['meminfo'] = ''
        try:
            cmd = 'cat /proc/meminfo'
            output = os.popen(cmd)
            data['meminfo'] = output.read()
            output.close()
        except:
            print( 'get_meminfo exception!')
            data['meminfo'] = ''
    return data['meminfo']

def get_freeinfo(sn, data, updated=0):
    if updated or 'freeinfo' not in data:
        try:
            cmd = 'free -m'
            output = os.popen(cmd)
            data['freeinfo'] = output.read()
            output.close()
        except:
            print( 'get_freeinfo exception!')
            data['freeinfo'] = ''
    return data['freeinfo']

def get_docker_freeinfo(sn, data, dockerid, updated=0):
    if updated or dockerid not in data or 'freeinfo' not in data[dockerid]:
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

        data[dockerid] = {}
        data[dockerid]['freeinfo'] = ''
        try:
            cmd = "%s exec -it %s bash -c 'free -m'"%(data['dockercmd'],dockerid)
            output = os.popen(cmd)
            data[dockerid]['freeinfo'] = output.read()
            output.close()
            if data[dockerid]['freeinfo'].find('command not found') >= 0:
                data[dockerid]['freeinfo'] = ''
        except:
            print( 'get_docker_freeinfo exception!')
            data[dockerid]['freeinfo'] = ''
    return data[dockerid]['freeinfo']

def get_docker_inspectinfo(sn, data, dockerid, updated=0):
    if updated or dockerid not in data or 'inspectinfo' not in data[dockerid]:
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

        data[dockerid] = {}
        data[dockerid]['inspectinfo'] = ''
        try:
            cmd = "%s inspect %s"%(data['dockercmd'],dockerid)
            output = os.popen(cmd)
            data[dockerid]['inspectinfo'] = output.read()
            output.close()
            data[dockerid]['inspectinfo'] = data[dockerid]['inspectinfo'].strip()
            if data[dockerid]['inspectinfo'].find('Error: No such') >= 0 or data[dockerid]['inspectinfo']=='[]':
                data[dockerid]['inspectinfo'] = ''
        except:
            print( 'get_docker_inspectinfo exception!')
            data[dockerid]['inspectinfo'] = ''
    return data[dockerid]['inspectinfo']

def get_hotfix_info(sn, data, updated=0):
    if updated or 'hotfix' not in data:
        try:
            cmd = 'khotfix-view -r 2>/dev/null'
            output = os.popen(cmd)
            data['hotfix'] = output.read()
            output.close()
        except:
            print( 'get_hotfix_info exception!')
            data['hotfix'] = ''
    return data['hotfix']

def get_tsar_data(sn, data, cmd, updated=0):
    if 'tsar' not in data:
        data['tsar'] = {}
    if updated or cmd not in data['tsar']:
        data['tsar'][cmd] = ''
        try:
            output = os.popen(cmd)
            data['tsar'][cmd] = output.read()
            output.close()
        except:
            print( 'get_tsar_data(cmd %s) exception!'%cmd)
            data['tsar'][cmd] = ''
    return data['tsar'][cmd]

def get_calltrace(sn, data, pid, updated=0):
    if 'bt' not in data:
        data['bt'] = {}
    if updated or pid not in data['bt']:
        data['bt'][pid] = ''
        try:
            cmd = 'for file in /proc/%s/task/*;do if [ -d $file ]; then if [ -f $file/stack ] && [ -f $file/stat ]; then cat $file/stat; cat $file/stack; fi; fi; done'%pid
            output = os.popen(cmd)
            data['bt'][pid] = output.read()
            output.close()
        except:
            print( 'get_calltrace(pid %s) exception!'%pid)
            data['bt'][pid] = ''
    return data['bt'][pid]

def get_all_calltraces(sn, data, updated=0):
    if updated or 'all_bt' not in data:
        data['all_bt'] = ''
        try:
            cmd = 'for file in /proc/*; do if [ -d $file ] && [ $file != /proc/self ]; then if [ -d $file/task ]; then for f2 in $file/task/* ; do if [ -d $f2 ]; then if [ -f $f2/stack ] && [ -f $f2/stat ]; then cat $f2/stat ; cat $f2/stack ; fi; fi; done;  fi; fi; done'
            output = os.popen(cmd)
            data['all_bt'] = output.read()
            output.close()
        except:
            print( 'get_all_calltraces exception!')
            data['all_bt'] = ''
    return data['all_bt']

def get_ps_info(sn, data, updated=0):
    if updated or 'ps' not in data:
        data['ps'] = ''
        try:
            cmd = 'ps -aux'
            output = os.popen(cmd)
            data['ps'] = output.read()
            output.close()
        except:
            print( 'get_ps_info exception!')
            data['ps'] = ''
    return data['ps']

def get_top_info(sn, data, updated=0):
    if updated or 'top' not in data:
        data['top'] = ''
        try:
            cmd = 'top -b -d 1 -n 2'
            output = os.popen(cmd)
            data['top'] = output.read()
            output.close()
        except:
            print( 'get_top_info exception!')
            data['top'] = ''
    return data['top']

def get_kernel_version(sn, data, updated=0):
    if 'version' not in data:
        data['version'] = ''
        try:
            cmd = 'cat /proc/version'
            output = os.popen(cmd)
            data['version'] = output.read()
            output.close()
        except:
            print( 'get_osversion_info exception!')
            data['version'] = ''
    return data['version']

def get_kernel_var(sn, data, var, updated=0):
    if 'var' not in data:
        data['var'] = {}
    if var not in data['var']:
        data['var'][var] = ''
    return data['var'][var]

def get_calltrace_by_crash(sn, data, task, updated=0):
    if 'bt_crash' not in data:
        data['bt_crash'] = {}
    if task not in data['bt_crash']:
        data['bt_crash'][task] = ''
    return data['bt_crash'][task]

def get_sysrq_info(sn, data, magic_key, updated=0):
    if 'sysrq' not in data:
        data['sysrq'] = {}
    if magic_key not in data['sysrq']:
        data['sysrq'][magic_key] = ''
    return data['sysrq'][magic_key]

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

def get_pid_stat(sn, pid):
    try:
        cmd = 'cat /proc/%s/stat 2>/dev/null'%(pid)
        output = os.popen(cmd)
        ret = output.read()
        output.close()
        ret = ret.split()[2]
        if ret.startswith('R'):
            return 'R'
        elif ret.startswith('D'):
            return 'D'
        elif ret.startswith('S'):
            return 'S'
        elif ret.startswith('Z'):
            return 'Z'
    except:
        pass
    return ''

SOFTLOCKUP_KEYWORD = 'BUG: soft lockup'
HUNGTASK_KEYWORD = 'blocked for more than'
RCUSTALL_KEYWORD = 'rcu_sched detected stalls'
rip_pattern = re.compile(r'.*\[\s*\S+\]\s*RIP:.*(\[<([0-9a-f]+)>\]|\[.*\])\s*(\S+)')
rip_pattern_1 = re.compile(r'.*\[\s*\S+\]\s*RIP:\s*0010:(\S+)')
calltrace_pattern = re.compile(r'.+[0-9]+\]\s+\[.*\]\s+(\S+)\+0x')
calltrace_pattern_1 = re.compile(r'.+[0-9]+\]\s+(\S+)\+0x')
ver_pattern = re.compile(r'Comm: (\S*).*(Tainted:|Not tainted).* (\S+) #')
vertype_pattern = re.compile(r'(\d+)\.(\d+)\.')
def get_rip_func(line):
    func_name = ""
    match = rip_pattern.match(line)
    if match:
        func_name = match.group(3).split("+0x")[0]
    else:
        match = rip_pattern_1.match(line)
        if match:
            func_name = match.group(1).split("+0x")[0]
    if func_name.find("[<ffff") >= 0 or func_name.startswith("0x"):
        func_name = ""
    return func_name

def extract_softlockup_calltrace(sn, dmesgs, data, updated=0):
    if not updated and 'softlockup_calltrace' in data:
        return data["softlockup_calltrace"]

    columns = []
    column = {"func_name":"","softlockupkey":""}
    dmesgs = dmesgs.splitlines()
    try:
        col = {}
        ct = {}
        calltrace = ''
        hit_softlockup = 0
        hit_calltrace = 0
        non_ct_num = 0
        func_name = ""
        for line in dmesgs:
            if SOFTLOCKUP_KEYWORD in line:
                if hit_softlockup == 1 and len(func_name) > 0 and len(calltrace) > 0:
                    col["func_name"] = func_name
                    col["softlockupkey"] = calltrace
                    columns.append(col)
                hit_softlockup = 1
                hit_calltrace = 0
                calltrace = ""
                func_name = ""
                non_ct_num = 0
            elif hit_softlockup == 1:
                idx = line.find('Comm:')
                if idx > 0:
                    match = ver_pattern.match(line, idx)
                    if match:
                        column['comm']=match.group(1)
                        column['ver']=match.group(3)

                if "RIP:" in line:
                    func_name = get_rip_func(line)
                    calltrace = func_name
                elif "Call Trace:" in line:
                    hit_calltrace = 1
                elif hit_calltrace == 1 and ("<IRQ>" in line or "<EOI>" in line or "?" in line):
                    non_ct_num = 0
                    continue
                else:
                    m = calltrace_pattern.match(line)
                    if m:
                        non_ct_num = 0
                        calltrace = "%s$%s"%(calltrace, m.group(1).split("+0x")[0])
                    else:
                        m = calltrace_pattern_1.match(line)
                        if m:
                            non_ct_num = 0
                            calltrace = "%s$%s"%(calltrace, m.group(1).split("+0x")[0])
                        else:
                            if hit_calltrace == 1:
                                non_ct_num += 1
                                if non_ct_num > 3:
                                    col["func_name"] = func_name
                                    col["softlockupkey"] = calltrace
                                    columns.append(col)
                                    calltrace = ""
                                    func_name = ""
                                    hit_softlockup = 0
        if len(func_name) > 0 and len(calltrace) > 0:
                col["func_name"] = func_name
                col["softlockupkey"] = calltrace
                columns.append(col)

    except Exception as e:
        print( repr(e))
        pass

    data["softlockup_calltrace"] = columns
    return data["softlockup_calltrace"]

