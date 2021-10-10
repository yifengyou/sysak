# -*- coding: utf-8 -*-
# @Author: lichen

import sys, os, socket
import time,datetime
import json, base64, hashlib, re
import threading
import sched
import subprocess
import sqlite3
import traceback
import zlib
import argparse
import oomcheck

if sys.version[0] == '2':
    from sets import Set as set

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
sys.path.append("%s/../rules/"%(os.path.dirname(os.path.abspath(__file__))))
sys.path.append("%s/../vmcore/"%(os.path.dirname(os.path.abspath(__file__))))
import collect_data
import crash
import utils
import cust_const

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

run_diag=0
run_panic=0
run_verbose = 0
run_offline = 0

PANIC_TYPE = 0
SOFTLOCKUP_TYPE = 1
HUNGTASK_TYPE = 2
RCUSTALL_TYPE = 3

SOFTLOCKUP_KEYWORD = 'BUG: soft lockup'
OOM_KEYWORD = 'invoked oom-killer'
RCUSTALL_KEYWORD = 'rcu_sched detected stalls'
SCHED_IN_ATOMIC = 'BUG: scheduling while atomic'
PAGE_ALLOC_FAIL = 'page allocation failure: order'
HUNG_TASK = 'blocked for more than'
HOTFIX_LOAD_ERR = 'activeness safety check failed'
KERNEL_WARNING = 'WARNING: CPU:'
LIST_CORRUPTION = ['list_add corruption','list_del corruption','list_add_rcu corruption']

EXT4FS_ERROR = 'EXT4-fs error'
EXT4FS_WARN = 'EXT4-fs warning'
IO_ERROR = 'Buffer I/O error on device'
FS_READONLY = 'Remounting filesystem read-only'
NF_CONNTRACK_TABLE_FULL = 'nf_conntrack: table full, dropping packet'

# HW errors
MCE_ERR="Machine Check Event"


rip_pattern = re.compile(r'.*\[\s*\S+\]\s*RIP:.*(\[<([0-9a-f]+)>\]|\[.*\])\s*(\S+)')
#rip_pattern = re.compile(r'.*\[\s*\S+\] RIP: .*\[<([0-9a-f]+)>\] (.+)')
rip_pattern_1 = re.compile(r'.*\[\s*\S+\]\s*RIP:\s*0010:(\S+)')
rip_pattern_2 = re.compile(r'.*RIP:.*:.*\s(\S+)+0x')
calltrace_pattern = re.compile(r'.+[0-9]+\]\s+(\S+)\+0x')
calltrace_pattern_1 = re.compile(r'.*\s+(\S+)\+0x')
calltrace_pattern_2 = re.compile(r'(\S+)\+0x')
ver_pattern = re.compile(r'Comm: (\S*).*(Tainted:|Not tainted).* (\S+) #')
vertype_pattern = re.compile(r'(\d+)\.(\d+)\.')
panic_pattern = re.compile(r'\[\s*\S+\] ((BUG: unable to handle kernel'
    '|Kernel panic|Bad pagetable:|divide error:|kernel BUG at'
    '|general protection fault:|invalid opcode:) .+)')

ignore_funcs = ["schedule","schedule_timeout","ret_from_fork","kthread",
        "do_syscall_64","entry_SYSCALL_64_after_swapgs","system_call_fastpath","fastpath",
        "entry_SYSCALL_64_after_hwframe",
        "page_fault","do_page_fault","_do_page_fault","worker_thread",
        "start_secondary","cpu_startup_entry","arch_cpu_idle","default_idle",
        "do_IRQ","common_interrupt","irq_exit","do_softirq",
        "__schedule","io_schedule_timeout","io_schedule","dump_stack",
        "exit_to_usermode_loop","stub_clone","schedule_preempt_disabled","oom_kill_process",
        "unwind_backtrace","dump_header","show_stack","dump_backtrace"]

def filter_calltrace(calltraces):
    cts = []
    for func in calltraces:
        if func not in ignore_funcs:
            cts.append(func)
    return cts

def dictfetchall(cursor):
    desc = cursor.description
    return [dict(zip([col[0] for col in desc], row)) for row in cursor.fetchall()]

def get_rip_func(line):
    func_name = ""
    match = rip_pattern.match(line)
    if match:
        func_name = match.group(3).split("+0x")[0]
    else:
        match = rip_pattern_1.match(line)
        if match:
            func_name = match.group(1).split("+0x")[0]
        else:
            match = rip_pattern_2.match(line)
            if match:
                func_name = match.group(1).split("+0x")[0]
    if func_name.find("[<ffff") >= 0 or func_name.startswith("0x"):
        func_name = ""
    return func_name

def extract_panic_calltrace(dmesgs,panic_list):
    column = {"func_name":"","calltrace":[]}
    try:
        pos = 0
        calltrace = []
        hit_calltrace = 0
        func_name = ""
        non_ct_lines = 0
        for line in dmesgs:
            pos += 1
            line = line.strip()
            if len(line) > 0:
                if "Comm:" in line:
                    idx = line.find('Comm:')
                    match = ver_pattern.match(line, idx)
                    if match:
                        column['comm']=match.group(1)
                        column['ver']=match.group(3)

                elif "RIP:" in line:
                    if hit_calltrace == 1:
                        break
                    func_name = get_rip_func(line)
                    calltrace.append(func_name)
                elif "Call Trace:" in line:
                    hit_calltrace = 1
                    del calltrace[:]
                elif hit_calltrace == 1 and ("<IRQ>" in line or "<EOI>" in line or "?" in line):
                    continue
                elif hit_calltrace == 1:
                    if line.find("<<EOE>>") > 0 or line.find("<EOE>") > 0:
                        del calltrace[:]
                    m = calltrace_pattern.match(line)
                    if m:
                        if 'panic' in m.group(1):
                            del calltrace[:]
                            continue
                        calltrace.append(m.group(1).split("+0x")[0])
                    else:
                        m = calltrace_pattern_1.match(line)
                        if m:
                            if 'panic' in m.group(1):
                                del calltrace[:]
                                continue
                            calltrace.append(m.group(1).split("+0x")[0])
                        else:
                            m = calltrace_pattern_2.match(line)
                            if m:
                                if 'panic' in m.group(1):
                                    del calltrace[:]
                                    continue
                                calltrace.append(m.group(1).split("+0x")[0])
                            else:
                                non_ct_lines += 1
                                if non_ct_lines >= 3:
                                    pos -= 3
                                    break
            if pos >= 100 and hit_calltrace == 0:
                pos = 1
                break
        if len(calltrace) > 2:
                column["func_name"] = func_name
                if len(func_name) > 0:
                    calltrace.insert(0,func_name)
                column["calltrace"] = calltrace
                del panic_list[:]
                panic_list.append(column)
    except Exception as e:
        print( repr(e))
        traceback.print_exc()
        pass

    return pos

def match_sim_issues(column,conn):
    # TBD
    return None
 

def extract_softlock_calltrace(dmesgs,softlock_list,conn):
    column = {"func_name":"","calltrace":[]}
    try:
        pos = 0
        calltrace = []
        hit_calltrace = 0
        func_name = ""
        non_ct_lines = 0
        for line in dmesgs:
            pos += 1
            line = line.strip()
            if len(line) > 0:
                if "Comm:" in line:
                    idx = line.find('Comm:')
                    match = ver_pattern.match(line, idx)
                    if match:
                        column['comm']=match.group(1)
                        column['ver']=match.group(3)

                elif "RIP:" in line:
                    func_name = get_rip_func(line)
                    calltrace.append(func_name)
                elif "Call Trace:" in line:
                    hit_calltrace = 1
                elif hit_calltrace == 1 and ("<IRQ>" in line or "<EOI>" in line or "?" in line):
                    continue
                elif hit_calltrace == 1:
                    m = calltrace_pattern.match(line)
                    if m:
                        calltrace.append(m.group(1).split("+0x")[0])
                    else:
                        m = calltrace_pattern_1.match(line)
                        if m:
                            calltrace.append(m.group(1).split("+0x")[0])
                        else:
                            m = calltrace_pattern_2.match(line)
                            if m:
                                calltrace.append(m.group(1).split("+0x")[0])
                            else:
                                non_ct_lines += 1
                                if non_ct_lines >= 3:
                                    pos -= 3
                                    break
            if pos >= 100 and hit_calltrace == 0:
                pos = 1
                break
        if len(calltrace) > 2:
                column["func_name"] = func_name
                column["calltrace"] = calltrace
                #if run_diag == 1:
                #    match_sim_issues(column,conn)
                softlock_list.append(column)

    except Exception as e:
        print( repr(e))
        traceback.print_exc()
        pass

    return pos

def extract_hungtask_calltrace(dmesgs,hungtask_list,conn):
    column = {"task":"","calltrace":[]}
    try:
        pos = 0
        calltrace = []
        hit_calltrace = 0
        task = ""
        non_ct_lines = 0
        for line in dmesgs:
            pos += 1
            line = line.strip()
            if len(line) > 0:
                if "blocked for more than" in line and len(task) == 0:
                    task = line.split('blocked for more than')[0].strip()
                    task = task.split()[-1].strip()
                elif "Call Trace:" in line:
                    hit_calltrace = 1
                elif hit_calltrace == 1 and ("<IRQ>" in line or "<EOI>" in line or "?" in line):
                    continue
                elif hit_calltrace == 1:
                    m = calltrace_pattern.match(line)
                    if m:
                        calltrace.append(m.group(1).split("+0x")[0])
                    else:
                        m = calltrace_pattern_1.match(line)
                        if m:
                            calltrace.append(m.group(1).split("+0x")[0])
                        else:
                            m = calltrace_pattern_2.match(line)
                            if m:
                                calltrace.append(m.group(1).split("+0x")[0])
                            else:
                                pos -= 1
                                break
            if pos >= 100 and hit_calltrace == 0:
                pos = 1
                break
        if len(calltrace) > 2:
                column["task"] = task
                column["calltrace"] = calltrace
                #if run_diag == 1:
                #    match_sim_issues(column,conn)
                hungtask_list.append(column)

    except Exception as e:
        print( repr(e))
        traceback.print_exc()
        pass

    return pos

def extract_calltrace(dmesgs,ct_list,conn):
    column = {"calltrace":[]}
    try:
        pos = 0
        calltrace = []
        non_ct_lines = 0
        for line in dmesgs:
            pos += 1
            line = line.strip()
            if len(line) > 0:
                if ("<IRQ>" in line or "<EOI>" in line or "?" in line):
                    continue
                m = calltrace_pattern.match(line)
                if m:
                    calltrace.append(m.group(1).split("+0x")[0])
                else:
                    m = calltrace_pattern_1.match(line)
                    if m:
                        calltrace.append(m.group(1).split("+0x")[0])
                    else:
                        m = calltrace_pattern_2.match(line)
                        if m:
                            calltrace.append(m.group(1).split("+0x")[0])
                        else:
                            non_ct_lines += 1
                            if non_ct_lines >= 3:
                                pos -= 3
                                break
        if len(calltrace) > 2:
                column["calltrace"] = calltrace
                #del misc_list[:]
                misc_list.append(column)

    except Exception as e:
        print( repr(e))
        traceback.print_exc()
        pass

    return pos

# check exception keywords
def keyword_check(dmesgs,ret,conn):
    return

def parse_dmesg(dmesgs,ret,conn):
    # check exception keywords
    keyword_check(dmesgs,ret,conn)

    try:
        dmesgs = dmesgs.splitlines()
        pos = -1
        next_pos = 0

        for line in dmesgs:
            pos += 1
            if next_pos > 0 and pos < next_pos:
                continue
            if SOFTLOCKUP_KEYWORD in line:
                ret['solution']['softlockup']['total_num'] += 1
                if ret['solution']['softlockup']['total_num'] > 10:
                    continue
                if run_diag:
                    nlines = extract_softlock_calltrace(dmesgs[pos:],
                        ret['solution']['softlockup']['detail'],conn)
                    next_pos = pos + nlines
            elif OOM_KEYWORD in line:
                ret['solution']['oom']['total_num'] += 1
            elif RCUSTALL_KEYWORD in line:
                ret['solution']['rcustall']['total_num'] += 1
                if ret['solution']['rcustall']['total_num'] > 10:
                    continue
            elif SCHED_IN_ATOMIC in line:
                ret['solution']['schedinatomic']['total_num'] += 1
            elif PAGE_ALLOC_FAIL in line:
                ret['solution']['pageallocfail']['total_num'] += 1
            elif HUNG_TASK in line:
                ret['solution']['hungtask']['total_num'] += 1
                if ret['solution']['hungtask']['total_num'] > 10:
                    continue
                if run_diag:
                    nlines = extract_hungtask_calltrace(dmesgs[pos:],
                        ret['solution']['hungtask']['detail'],conn)
                    next_pos = pos + nlines
            elif HOTFIX_LOAD_ERR in line:
                ret['solution']['hotfixloaderr']['total_num'] += 1
            elif 'corruption' in line:
                for key in LIST_CORRUPTION:
                    if key in line:
                        ret['solution']['listcorruption']['total_num'] += 1
            elif KERNEL_WARNING in line:
                ret['solution']['kernelwarn']['total_num'] += 1
                if ret['solution']['softlockup']['total_num'] > 10:
                    continue
                if run_diag:
                    nlines = extract_calltrace(dmesgs[pos:],
                        ret['solution']['kernelwarn']['detail'],conn)
                    next_pos = pos + nlines
            elif IO_ERROR in line:
                ret['solution']['ioerror']['total_num'] += 1
            elif EXT4FS_ERROR in line or EXT4FS_WARN in line:
                ret['solution']['ext4error']['total_num'] += 1
            elif FS_READONLY in line:
                ret['solution']['fsreadonly']['total_num'] += 1
            elif NF_CONNTRACK_TABLE_FULL in line:
                ret['solution']['nf_conntrack_table_full']['total_num'] += 1

        if run_verbose == 1:
            print( json.dumps(ret['solution'],ensure_ascii=False))

    except Exception as e:
        print( 'parse_dmesg exception:',repr(e))
        traceback.print_exc()
    return

def parse_syslog(ret,conn,data):
    #cmd = 'cat /var/log/messages | tail -n 10000 2>/dev/null'
    return

def parse_kern(ret,conn,data):
    """if 'kern' not in data:
        cmd = 'cat /var/log/kern | tail -n 10000 2>/dev/null'
        output = os.popen(cmd)
        kern = output.read().strip()
        output.close()
        data['kern'] = kern
    else:
        kern = data['kern']
    if len(kern) <= 0:
        return"""
    return

def query(sn,data,log_file=""):
    ret = {}
    ret['return'] = True
    ret['solution'] = {}
    ret['solution']['summary'] = ""
    ret['solution']['panic'] = {}
    ret['solution']['softlockup'] = {}
    ret['solution']['softlockup']['detail'] = []
    ret['solution']['softlockup']['total_num'] = 0
    ret['solution']['misc'] = {}
    ret['solution']['misc']['detail'] = []
    ret['solution']['misc']['total_num'] = 0
    ret['solution']['oom'] = {}
    ret['solution']['oom']['detail'] = []
    ret['solution']['oom']['total_num'] = 0
    ret['solution']['rcustall'] = {}
    ret['solution']['rcustall']['detail'] = []
    ret['solution']['rcustall']['total_num'] = 0
    ret['solution']['schedinatomic'] = {}
    ret['solution']['schedinatomic']['detail'] = []
    ret['solution']['schedinatomic']['total_num'] = 0
    ret['solution']['pageallocfail'] = {}
    ret['solution']['pageallocfail']['detail'] = []
    ret['solution']['pageallocfail']['total_num'] = 0
    ret['solution']['hungtask'] = {}
    ret['solution']['hungtask']['detail'] = []
    ret['solution']['hungtask']['total_num'] = 0
    ret['solution']['hotfixloaderr'] = {}
    ret['solution']['hotfixloaderr']['detail'] = []
    ret['solution']['hotfixloaderr']['total_num'] = 0
    ret['solution']['listcorruption'] = {}
    ret['solution']['listcorruption']['detail'] = []
    ret['solution']['listcorruption']['total_num'] = 0
    ret['solution']['kernelwarn'] = {}
    ret['solution']['kernelwarn']['detail'] = []
    ret['solution']['kernelwarn']['total_num'] = 0
    ret['solution']['ioerror'] = {}
    ret['solution']['ioerror']['detail'] = []
    ret['solution']['ioerror']['total_num'] = 0
    ret['solution']['ext4error'] = {}
    ret['solution']['ext4error']['detail'] = []
    ret['solution']['ext4error']['total_num'] = 0
    ret['solution']['fsreadonly'] = {}
    ret['solution']['fsreadonly']['detail'] = []
    ret['solution']['fsreadonly']['total_num'] = 0
    ret['solution']['nf_conntrack_table_full'] = {}
    ret['solution']['nf_conntrack_table_full']['detail'] = []
    ret['solution']['nf_conntrack_table_full']['total_num'] = 0

    ret['solution']['cust'] = {}

    global run_diag
    global run_panic
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
    run_panic = os.environ.get('run_panic')
    if run_panic is None:
        run_panic = 0
    else:
        run_panic = int(run_panic)

    hotfix = ''
    dmesgs = ""
    conn = None
    count = 0
    try:
        if run_panic == 1:
            ret['solution']['panic'] = parse_panic.query(sn,data,log_file)
        else:
            #conn = sqlite3.connect('%s/../vmcore/vmcore_sqlite.db'%(os.path.dirname(os.path.abspath(__file__))))
            #conn.text_factory = str
            #cursor = conn.cursor()
            if len(log_file) <= 0:
                if 'dmesg' not in data:
                    cmd = 'dmesg -T 2>/dev/null'
                    output = os.popen(cmd)
                    dmesgs = output.read().strip()
                    output.close()
                    data['dmesg'] = dmesgs
                else:
                    dmesgs = data['dmesg']
                parse_dmesg(dmesgs,ret,conn)
                parse_syslog(ret,conn,data)
                parse_kern(ret,conn,data)
            else:
                f = open(log_file,'r')
                while True:
                    dmesgs = f.read(65536)
                    if len(dmesgs) > 0:
                        count += 1
                        parse_dmesg(dmesgs,ret,conn)
                        dmesgs = ""
                    else:
                        break
                f.close()

        if ret['solution']['softlockup']['total_num'] > 0:
            ret['solution']['summary'] += "发生softlockup %s次\n"%(ret['solution']['softlockup']['total_num'])
            ret['solution']['cust']['softlockup'] = {}
            ret['solution']['cust']['softlockup']['category'] = cust_const.softlockup['category']
            ret['solution']['cust']['softlockup']['level'] = cust_const.softlockup['level']
            ret['solution']['cust']['softlockup']['name'] = cust_const.softlockup['name']
            ret['solution']['cust']['softlockup']['desc'] = cust_const.softlockup['desc']
            ret['solution']['cust']['softlockup']['solution'] = cust_const.softlockup['solution']
            ret['solution']['cust']['softlockup']['params'] = {}
            ret['solution']['cust']['softlockup']['params']['softlockup_total_num'] = ret['solution']['softlockup']['total_num']
            ret['solution']['cust']['softlockup']['summary'] = (
                cust_const.softlockup['summary_format']%(ret['solution']['cust']['softlockup']['params']['softlockup_total_num']))
            if run_diag:
                ret['solution']['summary'] += "诊断原因:\n"
                aones = {}
                for item in ret['solution']['softlockup']['detail']:
                    if len(item['solution']) > 0:
                        for aone in item['solution']:
                            if aone["issue_id"] != 0:
                                aones[aone["issue_id"]] = aone["hotfix"]
                if len(aones) > 0:
                    for aone in aones:
                        ret['solution']['summary'] += "疑似问题:Aone ID: https://work.aone.alibaba-inc.com/issue/%s, 关联hotfix: %s\n"%(
                            aone,aones[aone])
                        ret['solution']['cust']['softlockup']['summary'] += (
                            "疑似问题:Aone ID: https://work.aone.alibaba-inc.com/issue/%s, 关联hotfix: %s\n"%(
                            aone,aones[aone]))
        if ret['solution']['hungtask']['total_num'] > 0:
            ret['solution']['summary'] += "发生hungtask %s次\n"%(ret['solution']['hungtask']['total_num'])
            ret['solution']['cust']['hungtask'] = {}
            ret['solution']['cust']['hungtask']['category'] = cust_const.hungtask['category']
            ret['solution']['cust']['hungtask']['level'] = cust_const.hungtask['level']
            ret['solution']['cust']['hungtask']['name'] = cust_const.hungtask['name']
            ret['solution']['cust']['hungtask']['desc'] = cust_const.hungtask['desc']
            ret['solution']['cust']['hungtask']['solution'] = cust_const.hungtask['solution']
            ret['solution']['cust']['hungtask']['params'] = {}
            ret['solution']['cust']['hungtask']['params']['hungtask_total_num'] = ret['solution']['hungtask']['total_num']
            ret['solution']['cust']['hungtask']['summary'] = (
                 cust_const.hungtask['summary_format']%(ret['solution']['cust']['hungtask']['params']['hungtask_total_num']))
            if run_diag:
                ret['solution']['summary'] += "诊断原因:\n"
                aones = {}
                for item in ret['solution']['hungtask']['detail']:
                    if len(item['solution']) > 0:
                        for aone in item['solution']:
                            if aone["issue_id"] != 0:
                                aones[aone["issue_id"]] = aone["hotfix"]
                if len(aones) > 0:
                    for aone in aones:
                        ret['solution']['summary'] += "疑似问题:Aone ID: https://work.aone.alibaba-inc.com/issue/%s, 关联hotfix: %s\n"%(
                            aone,aones[aone])
                        ret['solution']['cust']['hungtask']['summary'] += (
                            "疑似问题:Aone ID: https://work.aone.alibaba-inc.com/issue/%s, 关联hotfix: %s\n"%(
                            aone,aones[aone]))
        if ret['solution']['rcustall']['total_num'] > 0:
            ret['solution']['summary'] += "发生rcustall %s次\n"%(ret['solution']['rcustall']['total_num'])
            ret['solution']['cust']['rcustall'] = {}
            ret['solution']['cust']['rcustall']['category'] = cust_const.rcustall['category']
            ret['solution']['cust']['rcustall']['level'] = cust_const.rcustall['level']
            ret['solution']['cust']['rcustall']['name'] = cust_const.rcustall['name']
            ret['solution']['cust']['rcustall']['desc'] = cust_const.rcustall['desc']
            ret['solution']['cust']['rcustall']['solution'] = cust_const.rcustall['solution']
            ret['solution']['cust']['rcustall']['params'] = {}
            ret['solution']['cust']['rcustall']['params']['rcustall_total_num'] = ret['solution']['rcustall']['total_num']
            ret['solution']['cust']['rcustall']['summary'] = (
                cust_const.rcustall['summary_format']%(ret['solution']['cust']['rcustall']['params']['rcustall_total_num']))
            if run_diag:
                ret['solution']['summary'] += "诊断原因:\n"
        if ret['solution']['schedinatomic']['total_num'] > 0:
            ret['solution']['summary'] += "发生schedinatomic %s次\n"%(ret['solution']['schedinatomic']['total_num'])
            ret['solution']['cust']['schedinatomic'] = {}
            ret['solution']['cust']['schedinatomic']['category'] = cust_const.schedinatomic['category']
            ret['solution']['cust']['schedinatomic']['level'] = cust_const.schedinatomic['level']
            ret['solution']['cust']['schedinatomic']['name'] = cust_const.schedinatomic['name']
            ret['solution']['cust']['schedinatomic']['desc'] = cust_const.schedinatomic['desc']
            ret['solution']['cust']['schedinatomic']['solution'] = cust_const.schedinatomic['solution']
            ret['solution']['cust']['schedinatomic']['params'] = {}
            ret['solution']['cust']['schedinatomic']['params']['schedinatomic_total_num'] = ret['solution']['schedinatomic']['total_num']
            ret['solution']['cust']['schedinatomic']['summary'] = (
                cust_const.schedinatomic['summary_format']%(ret['solution']['cust']['schedinatomic']['params']['schedinatomic_total_num']))
            if run_diag:
                ret['solution']['summary'] += "诊断原因:\n"
        if ret['solution']['pageallocfail']['total_num'] > 0:
            ret['solution']['summary'] += "发生pageallocfail %s次\n"%(ret['solution']['pageallocfail']['total_num'])
            ret['solution']['cust']['pageallocfail'] = {}
            ret['solution']['cust']['pageallocfail']['category'] = cust_const.pageallocfail['category']
            ret['solution']['cust']['pageallocfail']['level'] = cust_const.pageallocfail['level']
            ret['solution']['cust']['pageallocfail']['name'] = cust_const.pageallocfail['name']
            ret['solution']['cust']['pageallocfail']['desc'] = cust_const.pageallocfail['desc']
            ret['solution']['cust']['pageallocfail']['solution'] = cust_const.pageallocfail['solution']
            ret['solution']['cust']['pageallocfail']['params'] = {}
            ret['solution']['cust']['pageallocfail']['params']['pageallocfail_total_num'] = ret['solution']['pageallocfail']['total_num']
            ret['solution']['cust']['pageallocfail']['summary'] = (
                cust_const.pageallocfail['summary_format']%(ret['solution']['cust']['pageallocfail']['params']['pageallocfail_total_num']))
            if run_diag:
                ret['solution']['summary'] += "诊断原因:\n"
        if ret['solution']['oom']['total_num'] > 0:
            ret['solution']['summary'] += "发生oom %s次\n"%(ret['solution']['oom']['total_num'])
            ret['solution']['cust']['oom'] = {}
            ret['solution']['cust']['oom']['category'] = cust_const.oom['category']
            ret['solution']['cust']['oom']['level'] = cust_const.oom['level']
            ret['solution']['cust']['oom']['name'] = cust_const.oom['name']
            ret['solution']['cust']['oom']['desc'] = cust_const.oom['desc']
            ret['solution']['cust']['oom']['solution'] = cust_const.oom['solution']
            ret['solution']['cust']['oom']['params'] = {}
            ret['solution']['cust']['oom']['params']['oom_total_num'] = ret['solution']['oom']['total_num']
            ret['solution']['cust']['oom']['summary'] = (
                cust_const.oom['summary_format']%(ret['solution']['cust']['oom']['params']['oom_total_num']))
            if run_diag:
                ret['solution']['summary'] += "诊断原因:\n"
                ret['solution']['summary'] += oomcheck.oom_scan(sn, data, 1)
        if ret['solution']['hotfixloaderr']['total_num'] > 0:
            ret['solution']['summary'] += "发生hotfix装载失败报警 %s次\n"%(ret['solution']['hotfixloaderr']['total_num'])
            ret['solution']['cust']['hotfixloaderr'] = {}
            ret['solution']['cust']['hotfixloaderr']['category'] = cust_const.hotfixloaderr['category']
            ret['solution']['cust']['hotfixloaderr']['level'] = cust_const.hotfixloaderr['level']
            ret['solution']['cust']['hotfixloaderr']['name'] = cust_const.hotfixloaderr['name']
            ret['solution']['cust']['hotfixloaderr']['desc'] = cust_const.hotfixloaderr['desc']
            ret['solution']['cust']['hotfixloaderr']['solution'] = cust_const.hotfixloaderr['solution']
            ret['solution']['cust']['hotfixloaderr']['params'] = {}
            ret['solution']['cust']['hotfixloaderr']['params']['hotfixloaderr_total_num'] = ret['solution']['hotfixloaderr']['total_num']
            ret['solution']['cust']['hotfixloaderr']['summary'] = (
                cust_const.hotfixloaderr['summary_format']%(ret['solution']['cust']['hotfixloaderr']['params']['hotfixloaderr_total_num']))
            if run_diag:
                ret['solution']['summary'] += "诊断原因:\n"
        if ret['solution']['listcorruption']['total_num'] > 0:
            ret['solution']['summary'] += "发生listcorruption %s次\n"%(ret['solution']['listcorruption']['total_num'])
            ret['solution']['cust']['listcorruption'] = {}
            ret['solution']['cust']['listcorruption']['category'] = cust_const.listcorruption['category']
            ret['solution']['cust']['listcorruption']['level'] = cust_const.listcorruption['level']
            ret['solution']['cust']['listcorruption']['name'] = cust_const.listcorruption['name']
            ret['solution']['cust']['listcorruption']['desc'] = cust_const.listcorruption['desc']
            ret['solution']['cust']['listcorruption']['solution'] = cust_const.listcorruption['solution']
            ret['solution']['cust']['listcorruption']['params'] = {}
            ret['solution']['cust']['listcorruption']['params']['listcorruption_total_num'] = ret['solution']['listcorruption']['total_num']
            ret['solution']['cust']['listcorruption']['summary'] = (
                cust_const.listcorruption['summary_format']%(ret['solution']['cust']['listcorruption']['params']['listcorruption_total_num']))
            if run_diag:
                ret['solution']['summary'] += "诊断原因:\n"
        if ret['solution']['kernelwarn']['total_num'] > 0:
            ret['solution']['summary'] += "发生kernelwarn %s次\n"%(ret['solution']['kernelwarn']['total_num'])
            ret['solution']['cust']['kernelwarn'] = {}
            ret['solution']['cust']['kernelwarn']['category'] = cust_const.kernelwarn['category']
            ret['solution']['cust']['kernelwarn']['level'] = cust_const.kernelwarn['level']
            ret['solution']['cust']['kernelwarn']['name'] = cust_const.kernelwarn['name']
            ret['solution']['cust']['kernelwarn']['desc'] = cust_const.kernelwarn['desc']
            ret['solution']['cust']['kernelwarn']['solution'] = cust_const.kernelwarn['solution']
            ret['solution']['cust']['kernelwarn']['params'] = {}
            ret['solution']['cust']['kernelwarn']['params']['kernelwarn_total_num'] = ret['solution']['kernelwarn']['total_num']
            ret['solution']['cust']['kernelwarn']['summary'] = (
                cust_const.kernelwarn['summary_format']%(ret['solution']['cust']['kernelwarn']['params']['kernelwarn_total_num']))
            if run_diag:
                ret['solution']['summary'] += "诊断原因:\n"
        if ret['solution']['ioerror']['total_num'] > 0:
            ret['solution']['summary'] += "发生ioerror %s次\n"%(ret['solution']['ioerror']['total_num'])
            ret['solution']['cust']['ioerror'] = {}
            ret['solution']['cust']['ioerror']['category'] = cust_const.ioerror['category']
            ret['solution']['cust']['ioerror']['level'] = cust_const.ioerror['level']
            ret['solution']['cust']['ioerror']['name'] = cust_const.ioerror['name']
            ret['solution']['cust']['ioerror']['desc'] = cust_const.ioerror['desc']
            ret['solution']['cust']['ioerror']['solution'] = cust_const.ioerror['solution']
            ret['solution']['cust']['ioerror']['params'] = {}
            ret['solution']['cust']['ioerror']['params']['ioerror_total_num'] = ret['solution']['ioerror']['total_num']
            ret['solution']['cust']['ioerror']['summary'] = (
                cust_const.ioerror['summary_format']%(ret['solution']['cust']['ioerror']['params']['ioerror_total_num']))
            if run_diag:
                ret['solution']['summary'] += "诊断原因:\n"
        if ret['solution']['fsreadonly']['total_num'] > 0:
            ret['solution']['summary'] += "发生fsreadonly %s次\n"%(ret['solution']['fsreadonly']['total_num'])
            ret['solution']['cust']['fsreadonly'] = {}
            ret['solution']['cust']['fsreadonly']['category'] = cust_const.fsreadonly['category']
            ret['solution']['cust']['fsreadonly']['level'] = cust_const.fsreadonly['level']
            ret['solution']['cust']['fsreadonly']['name'] = cust_const.fsreadonly['name']
            ret['solution']['cust']['fsreadonly']['desc'] = cust_const.fsreadonly['desc']
            ret['solution']['cust']['fsreadonly']['solution'] = cust_const.fsreadonly['solution']
            ret['solution']['cust']['fsreadonly']['params'] = {}
            ret['solution']['cust']['fsreadonly']['params']['fsreadonly_total_num'] = ret['solution']['fsreadonly']['total_num']
            ret['solution']['cust']['fsreadonly']['summary'] = (
                cust_const.fsreadonly['summary_format']%(ret['solution']['cust']['fsreadonly']['params']['fsreadonly_total_num']))
            if run_diag:
                ret['solution']['summary'] += "诊断原因:\n"
        if ret['solution']['ext4error']['total_num'] > 0:
            ret['solution']['summary'] += "发生ext4error %s次\n"%(ret['solution']['ext4error']['total_num'])
            ret['solution']['cust']['ext4error'] = {}
            ret['solution']['cust']['ext4error']['category'] = cust_const.ext4error['category']
            ret['solution']['cust']['ext4error']['level'] = cust_const.ext4error['level']
            ret['solution']['cust']['ext4error']['name'] = cust_const.ext4error['name']
            ret['solution']['cust']['ext4error']['desc'] = cust_const.ext4error['desc']
            ret['solution']['cust']['ext4error']['solution'] = cust_const.ext4error['solution']
            ret['solution']['cust']['ext4error']['params'] = {}
            ret['solution']['cust']['ext4error']['params']['ext4error_total_num'] = ret['solution']['ext4error']['total_num']
            ret['solution']['cust']['ext4error']['summary'] = (
                cust_const.ext4error['summary_format']%(ret['solution']['cust']['ext4error']['params']['ext4error_total_num']))
            if run_diag:
                ret['solution']['summary'] += "诊断原因:\n"
        if ret['solution']['nf_conntrack_table_full']['total_num'] > 0:
            ret['solution']['summary'] += "发生nf_conntrack_table_full %s次\n"%(ret['solution']['nf_conntrack_table_full']['total_num'])
            ret['solution']['cust']['nf_conntrack_table_full'] = {}
            ret['solution']['cust']['nf_conntrack_table_full']['category'] = cust_const.nf_conntrack_table_full['category']
            ret['solution']['cust']['nf_conntrack_table_full']['level'] = cust_const.nf_conntrack_table_full['level']
            ret['solution']['cust']['nf_conntrack_table_full']['name'] = cust_const.nf_conntrack_table_full['name']
            ret['solution']['cust']['nf_conntrack_table_full']['desc'] = cust_const.nf_conntrack_table_full['desc']
            ret['solution']['cust']['nf_conntrack_table_full']['solution'] = cust_const.nf_conntrack_table_full['solution']
            ret['solution']['cust']['nf_conntrack_table_full']['params'] = {}
            ret['solution']['cust']['nf_conntrack_table_full']['params']['nf_conntrack_table_full_total_num'] = ret['solution']['nf_conntrack_table_full']['total_num']
            ret['solution']['cust']['nf_conntrack_table_full']['summary'] = (
                cust_const.nf_conntrack_table_full['summary_format']%(ret['solution']['nf_conntrack_table_full']['total_num']))
            if run_diag:
                ret['solution']['summary'] += "诊断原因:\n"
    except Exception as e:
        print( 'log_diag exception:',repr(e))
        traceback.print_exc()
        pass
    finally:
        if (conn):
            conn.close()

    if run_verbose == 1:
        print( __name__,':',ret)
    return ret

def main():
    sn = ''
    data = {}

    global run_offline
    global run_diag
    global run_verbose

    parser = argparse.ArgumentParser()
    parser.add_argument('-o','--offline', action='store_true', help='run in offline, no network available.')
    parser.add_argument('-v','--verbose', action='store_true', help='enable debugging log.')
    parser.add_argument('-d','--diag', action='store_true', help='run diag mode to diagnose OS exceptions.')
    args = vars(parser.parse_args())
    if args.get('offline',False) == True:
        run_offline = 1
        os.environ['run_offline']=str(run_offline)
    if args.get('diag',False) == True:
        run_diag = 1
        os.environ['run_diag']=str(run_diag)
    if args.get('verbose',False) == True:
        run_verbose = 1
        os.environ['run_verbose']=str(run_verbose)

    ret = query(sn, data)
    if ret['return']:
        result = {os.path.basename(__file__)[:-3]:ret['solution']}
        result = json.dumps(result,ensure_ascii=False)
        print(result)
        utils.post_ossre_diag(result)

if __name__ == "__main__":
    main()
