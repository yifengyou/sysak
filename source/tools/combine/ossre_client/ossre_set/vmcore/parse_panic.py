# -*- coding: utf-8 -*-
# @Author: lichen/zhilan

import os
import sys
import time
import subprocess
import re 
import sqlite3
import json
import traceback
import importlib
import argparse
import vmcore_const

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
import crash
import collect_data
import utils

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

# crashkey_type={
# 0:func_name
# 1:calltrace
# 2:crashkey
# 3:bugon_file
#}

ltime_pattern = re.compile(r'^\[\s*([0-9]+)\..*\]')
rip_pattern = re.compile(r'\[\s*\S+\] RIP: 0010:.*(\[<([0-9a-f]+)>\]|\[.*\]) (.+)')
bugat_pattern = re.compile(r'.+\] kernel BUG at (\S+)!')
ver_pattern = re.compile(r'Comm: (\S*).*(Tainted:|Not tainted).* (\S+) #')
unload_pattern = re.compile(r'\[last unloaded: (\S+)\]')
title_pattern = re.compile(r'\[\s*\S+\] ((BUG:|Kernel panic|Bad pagetable:|divide error:|kernel BUG at|general protection fault:) .+)')
vertype_pattern = re.compile(r'(\d+)\.(\d+)\.')
last_strhost = ''

def get_column_value(column, line):
    match = rip_pattern.match(line)
    if match:
        column['rip'] = match.group(2)
        if match.group(2) is None:
            column['rip'] = '[]'
        column['func_name'] = match.group(3)
    match = bugat_pattern.match(line)
    if match:
        column['bugat'] = match.group(1)
    idx = line.find('Comm:')
    if idx > 0:
        match = ver_pattern.match(line, idx)
        if match:
            column['comm'] = match.group(1)
            column['ver'] = match.group(3)
    idx = line.find('[last unloaded:')
    if idx > 0:
        match = unload_pattern.match(line, idx)
        if match:
            column['unload'] = match.group(1)
    match = title_pattern.match(line)
    if match and len(column['title']) <= 0:
        column['title'] = match.group(1)

def get_stamp(line):
    match = ltime_pattern.match(line)
    if match:
        return int(match.group(1))
    return 0

def get_last_time(f):
    ret = 10
    try:
        f.seek(-512, os.SEEK_END)
    except:
        pass
    for line in f.readlines():
        ret = get_stamp(line)
        if ret > 0:
            break
    f.seek(0, os.SEEK_SET)
    return ret-10

def fix_func_name(column):
    if column['dmesg'].find('SysRq : Trigger a crash') > 0:
        column['func_name'] = 'sysrq_handle_crash'
        column['title'] = 'sysrq: SysRq : Trigger a crash'
        column['status'] = vmcore_const.STATUS_SYSRQ
        column['crashkey_type'] = 2
        column['crashkey'] = 'sysrq_handle_crash'
    if column['dmesg'].find('Kernel panic - not syncing: Fatal machine check') > 0:
        column['func_name'] = 'fatal_machine_check'
        column['title'] = 'Kernel panic - not syncing: Fatal machine check'
        column['status'] = vmcore_const.STATUS_HWERROR
        column['crashkey_type'] = 2
        column['crashkey'] = 'fatal_machine_check'
    if column['dmesg'].find('Kernel panic - not syncing: Fatal hardware error') > 0:
        column['func_name'] = 'fatal_hardware_error'
        column['title'] = 'Kernel panic - not syncing: Fatal machine check'
        column['status'] = vmcore_const.STATUS_HWERROR
        column['crashkey_type'] = 2
        column['crashkey'] = 'fatal_hardware_error'
    if column['dmesg'].find('Fatal local machine check') > 0:
        column['func_name'] = 'fatal_machine_check'
        column['title'] = 'Kernel panic - not syncing: Fatal local machine check'
        column['status'] = vmcore_const.STATUS_HWERROR
        column['crashkey_type'] = 2
        column['crashkey'] = 'fatal_machine_check'
    if 'bugat' in column:
        column['bugon_file'] = column['bugat'].split(':')[0]
        column['crashkey_type'] = 3

def parse_file(name, column):
    f = open(name, 'r')
    result = ''
    for line in f.readlines():
        if line.find('Modules linked in') >= 0:
            column['modules'] = line[line.find(':')+1:]
        result += line
        get_column_value(column, line)
    f.close()
    column['dmesg'] = result
    column['dmesg_file'] = name
    fix_func_name(column)

def parse_rawdmesg(column):
    dmesgs = column['rawdmesg'].splitlines()
    column['rawdmesg'] = ''
    result = ''
    for line in dmesgs:
        if line.find('Modules linked in') >= 0:
            column['modules'] = line[line.find(':')+1:]
        result += line
        get_column_value(column, line)
    column['dmesg'] = result
    fix_func_name(column)

line_pattern = re.compile(r'.+[0-9]+\]\s+\[.*\][? ]* (\S+)\+0x')
def get_calltrace(column):
    list1 = []
    lines = column['dmesg'].split('\n')
    for r in lines:
        if r.find("Call Trace:") > 0 or r.find("<<EOE>>") > 0 or r.find("<EOE>") > 0:
            del list1[:]
        m = line_pattern.match(r)
        if m:
            if m.group(1) == 'panic':
                del list1[:]
                continue
            list1.append(m.group(1))
    calltrace = column['func_name']
    if calltrace != '':
        calltrace = calltrace.split('+')[0]
    if len(list1) > 2:
        list1 = list1[0:2]
    for i in list1:
        calltrace = ''.join([calltrace,'$',i])
    column['calltrace'] = calltrace

def fixup_panic(column):
    result = False
    try:
        for subdir, dirs, files in os.walk(os.path.dirname(os.path.abspath(__file__))):
            for file in files:
                filepath = subdir + os.sep + file
                if os.path.isfile(filepath) and file.endswith('.py') and file.startswith('fixup_'):
                    fixup_mod = file[:-3]
                    mod = importlib.import_module(fixup_mod)
                    result = mod.fixup_issue_status(column)
                    if result == True:
                        return result
    except Exception as e:
        print( 'fixup_issue_status Exception!',e)
    finally:
        return result

def check_panic(column,conn):
    if 'rawdmesg' not in column and os.path.isfile(column['filename']) == False:
        return

    matched = False
    if 'rawdmesg' in column:
        parse_rawdmesg(column)
    else:
        parse_file(column['filename'], column)

    m = vertype_pattern.match(column['ver'])
    if m:
        column['vertype'] = int(m.group(1)) * 100 + int(m.group(2))

    get_calltrace(column)
    if len(column['calltrace']) <= 0:
        column['crashkey_type'] = 0
    if column['crashkey_type'] == 0 and len(column['func_name']) > 0:
        column['crashkey'] = '%d$%s'%(column['vertype'],column['func_name'])
    elif column['crashkey_type'] == 1 and len(column['calltrace']) > 0:
        column['crashkey'] = '%d$%s'%(column['vertype'],column['calltrace'])
    elif column['crashkey_type'] == 2 and len(column['crashkey']) > 0:
        column['crashkey'] = '%d$%s'%(column['vertype'],column['crashkey'])
    elif column['crashkey_type'] == 3 and len(column['bugon_file']) > 0:
        column['crashkey'] = '%d$%s$%s'%(column['vertype'],column['bugon_file'],column['calltrace'])

    cursor = conn.cursor()
    issue_id = ''
    if len(column['bugon_file']) > 0:
        sql = 'select issue_id,vertype from panic where bugon_file=? and instr(?,calltrace)!=0'
        value = (column['bugon_file'],column['calltrace'],)
        cursor.execute(sql, value)
        rows = cursor.fetchall()
        if len(rows) <= 0:
            sql = 'select issue_id,vertype from panic where bugon_file=? and instr(calltrace,?)!=0'
            cursor.execute(sql, value)
            rows = cursor.fetchall()
        for row in rows:
            if row[1] == column['vertype'] or len(issue_id) <= 0:
                issue_id = row[0]
    else:
        sql = 'select issue_id,vertype from panic where instr(?,calltrace)!=0'
        value = (column['calltrace'],)
        cursor.execute(sql, value)
        rows = cursor.fetchall()
        if len(rows) <= 0:
            sql = 'select issue_id,vertype from panic where instr(?,calltrace)!=0'
            cursor.execute(sql, value)
            rows = cursor.fetchall()
        for row in rows:
            if row[1] == column['vertype'] or len(issue_id) <= 0:
                issue_id = row[0]
 
    sql = 'select commitid,solution from issue where issue_id=?'
    value = (issue_id,)
    cursor.execute(sql, value)
    row = cursor.fetchone()
    if row:
        if len(row[0]) > 0 and len(row[1]) > 0:
            column['commitid'] = row[0]
            column['solution'] = row[1]
        elif len(row[0]) > 0:
            column['commitid'] = row[0]
            column['solution'] = ("疑似upstream fix:%s"%(row[0]))

    cursor.close()
    fixup_panic(column)

    if (len(column['commitid']) > 0 or len(column['solution']) > 0):
        matched = True
    return matched

def do_cmd(cmd):
    output = os.popen(cmd)
    ret = output.read().strip()
    output.close()
    return ret

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
                            part = do_cmd(cmd).splitlines()[-1].split()[-1]
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
    except Exception as e:
        print( 'get_crash_path:',e)
        pass
        return '/var/crash/'

def init_column(column):
    column['rip'] = ''
    column['comm'] = ''
    column['ver'] = ''
    column['vertype'] = 0
    column['func_name'] = ''
    column['title'] = ''
    column['status'] = 0
    column['hwerr'] = ''
    column['calltrace'] = ''
    column['bugon_file'] = ''
    column['crashkey_type'] = 1
    column['crashkey'] = ''
    column['modules'] = ''
    column['cause'] = ''
    column['commitid'] = ''
    column['solution'] = ''

def query(sn, data, log_file="", crashonly=0):
    ret = {}
    ret['return'] = False
    ret['solution'] = []
    column = {}

    try:
        conn = sqlite3.connect('%s/vmcore_sqlite.db'%(os.path.dirname(os.path.abspath(__file__))))
        conn.text_factory = str

        if crashonly == 1:
            result = {}
            vmcore_file = data['vmcore']
            vmlinux_file = data['vmlinux']
            crash_inst = collect_data.get_live_crash(sn, data)
            dmesgs = crash_inst.cmd("log")
            init_column(column)
            column['rawdmesg'] = dmesgs
            matched = check_panic(column,conn)
            result['vmcore_file'] = vmcore_file
            if matched:
                ret['return'] = True
                if len(column['commitid']) > 0:
                    result['commitid'] = column['commitid']
                if len(column['solution']) > 0:
                    result['solution'] = column['solution']
                if len(column['cause']) > 0:
                    result['cause'] = column['cause']
            else:
                result['solution'] = "没有匹配到已知的宕机问题，请联系内核同学!"

            if column['status'] == vmcore_const.STATUS_SYSRQ:
                ret['return'] = True
                result["cause"] = "该宕机为手动触发宕机!"
            elif column['status'] == vmcore_const.STATUS_HWERROR:
                ret['return'] = True
                result["cause"] = "该宕机为硬件错误导致宕机!"
            ret['solution'].append(result)
        elif len(log_file) > 0:
            result = {}
            init_column(column)
            column['filename'] = log_file
            column['ver'] = ''
            result['dmesg_file'] = log_file
            matched = check_panic(column,conn)
            if matched:
                ret['return'] = True
                if len(column['commitid']) > 0:
                    result['commitid'] = column['commitid']
                if len(column['solution']) > 0:
                    result['solution'] = column['solution']
                if len(column['cause']) > 0:
                    result['cause'] = column['cause']
            else:
                result['solution'] = "没有匹配到已知的宕机问题，请联系内核同学!"

            if column['status'] == vmcore_const.STATUS_SYSRQ:
                ret['return'] = True
                result["cause"] = "该宕机为手动触发宕机!"
            elif column['status'] == vmcore_const.STATUS_HWERROR:
                ret['return'] = True
                result["cause"] = "该宕机为硬件错误导致宕机!"
            ret['solution'].append(result)
        else:    
            for subdir, dirs, files in os.walk(get_crash_path()):
                for file in files:
                    result = {}
                    filepath = subdir + os.sep + file
                    if os.path.isfile(filepath) and filepath.endswith('-dmesg.txt'):
                        init_column(column)
                        column['filename'] = filepath 
                        column['ver'] = ''
                        result['dmesg_file'] = filepath
                        matched = check_panic(column,conn)
                        if matched:
                            ret['return'] = True
                            if len(column['commitid']) > 0:
                                result['commitid'] = column['commitid']
                            if len(column['solution']) > 0:
                                result['solution'] = column['solution']
                            if len(column['cause']) > 0:
                                result['cause'] = column['cause']
                        else:
                            result['solution'] = "没有匹配到已知的宕机问题，请联系内核同学!"
                        if column['status'] == vmcore_const.STATUS_SYSRQ:
                            ret['return'] = True
                            result["cause"] = "该宕机为手动触发宕机!"
                        elif column['status'] == vmcore_const.STATUS_HWERROR:
                            ret['return'] = True
                            result["cause"] = "该宕机为硬件错误导致宕机!"
                        ret['solution'].append(result)
    except Exception as e:
        print("Exception in check_vmcores!",e)
        traceback.print_exc()
    finally:
        column['dmesg'] = ""
        if (conn):
            conn.close()
        print ('VMCORE:%s' %( json.dumps(ret, ensure_ascii=False)))
        return ret

def main():
    data = {}
    log_file = ""
    parser = argparse.ArgumentParser()
    parser.add_argument('-l','--log', help='run log parse with specified log file only.')
    args = vars(parser.parse_args())
    if args.get('log',None) is not None:
        log_file = args.get('log',None)

    query(None, data, log_file)

if __name__ == "__main__":
    main()
