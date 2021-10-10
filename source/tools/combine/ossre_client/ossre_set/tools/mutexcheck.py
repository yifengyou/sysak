# -*- coding: utf-8 -*-
# @Author: shiyan

import os, socket, sys
import time,datetime
import json, base64, hashlib, re

if sys.path[0].find('tools') > 0:
    sys.path.append("%s/../"%(sys.path[0]))
else:
    sys.path.append("%s/tools"%(sys.path[0]))

import crash
import collect_data

def deadlock_check(figure):
    for mutex_1 in figure['mutex']:
        for mutex_2 in figure['mutex']:
            for owner_1 in figure['mutex'][mutex_1]['owner_task']:
                if owner_1 in figure['mutex'][mutex_2]['waiting_task']:
                    for owner_2 in figure['mutex'][mutex_2]['owner_task']:
                        if owner_2 in figure['mutex'][mutex_1]['waiting_task']:
                            print( "---------------mutex deadlock---------------")
                            print( "task: %10s\nowned   mutex: %20s %20s\nwaiting mutex: %20s %20s\n"\
                                   %(figure['mutex'][mutex_1]['owner_task'], figure['mutex'][mutex_1]['name'],\
                                     mutex_1, figure['mutex'][mutex_2]['name'], mutex_2))
                            print( "task: %10s\nowned   mutex: %20s %20s\nwaiting mutex: %20s %20s\n"\
                                   %(figure['mutex'][mutex_2]['owner_task'], figure['mutex'][mutex_2]['name'],\
                                     mutex_2, figure['mutex'][mutex_1]['name'], mutex_1))

def mutex_check(sn, data, figure):
    global live_crash
    un_task = []
    un_task_pid = []
    figure['mutex'] = {}
    print( "mutex checking ......")

    version = collect_data.get_kernel_version(sn, data)
    if '3.10' in version or '4.9' in version:
        mutex_stack_flag = '__mutex_lock_slowpath'
        mutex_begin = '__mutex_lock_slowpath'
        mutex_end = 'mutex_lock at'
        lock_offset = -7
    elif '4.19' in version:
        mutex_stack_flag = '__mutex_lock'
        mutex_begin = '__schedule at'
        mutex_end = 'schedule at'
        lock_offset = -5
    else:
        print( "not supported version: %s"%version)
        return


    crash_inst = collect_data.get_live_crash(sn, data)
    ps_task = crash_inst.cmd("ps").strip()
    ps_task = ps_task.splitlines()

    for ps in ps_task:
        ps = ps.strip()
        if  ps.find('UN') > 0:
            un_task.append(ps)

    for task in un_task:
        task =task.strip().split()
        un_task_pid.append(task[0])

    for pid in un_task_pid:
        task_bt_f = crash_inst.cmd('bt -f %s'%pid)
        task_bt_F = crash_inst.cmd('bt -F %s'%pid)

        if len(task_bt_f) <= 0 or len(task_bt_F) <= 0:
            continue
        if task_bt_f.find(mutex_stack_flag) < 0:
            continue
        task_bt_f = task_bt_f.splitlines()
        task_bt_F = task_bt_F.splitlines()
        reach_mutex = 0
        bt_addr_f = []
        for line in task_bt_f:
            line = line.strip()
            if line.find(mutex_begin) >= 0:
                reach_mutex = 1
            elif reach_mutex == 1 and line.find(mutex_end) >= 0:
                break
            elif reach_mutex == 1:
                index = line.index(':')
                line = line[index+1:].strip().split()
                for addr in line:
                    bt_addr_f.append(addr)
        if len(bt_addr_f) < 7:
            continue
        mutex = bt_addr_f[lock_offset]

        if mutex not in figure['mutex']:
            figure['mutex'][mutex] = {}
            figure['mutex'][mutex]['owner_task'] = {}
            figure['mutex'][mutex]['waiting_task'] = {}

        reach_mutex = 0
        bt_addr_F = []
        for line in task_bt_F:
            line = line.strip()
            if line.find(mutex_begin) >= 0:
                reach_mutex = 1
            elif reach_mutex == 1 and line.find(mutex_end) >= 0:
                break
            elif reach_mutex == 1:
                index = line.index(':')
                line = line[index+1:].strip().split()
                for addr in line:
                    bt_addr_F.append(addr)
        if len(bt_addr_F) < 7:
            continue
        mutex_name = bt_addr_F[lock_offset]
        figure['mutex'][mutex]['name'] = mutex_name

        waiting_name = crash_inst.cmd('bt %s'%(pid)).strip()
        if len(waiting_name) <= 0 or waiting_name.find('COMMAND') < 0:
            continue
        waiting_name = waiting_name.split('COMMAND:')[-1].strip().splitlines()[0].strip('\"')

        figure['mutex'][mutex]['waiting_task'][pid] = waiting_name

        if not crash.valid_kernel_ptr('0x%s'%(mutex)):
            continue

        if '3.10' in version or '4.9' in version:
            owner_addr = crash_inst.cmd('struct mutex.owner 0x%s'%(mutex)).strip()
            if len(owner_addr) <= 0 or owner_addr.find('owner =') < 0:
                continue
            owner_addr = owner_addr.split('=')[-1].strip('')
            if not crash.valid_kernel_ptr(owner_addr):
                continue
        elif '4.19' in version:
            owner_addr = crash_inst.cmd('struct mutex.owner.counter 0x%s'%(mutex)).strip()
            if len(owner_addr) <= 0 or owner_addr.find('owner.counter') < 0:
                continue
            owner_addr = owner_addr.split('=')[-1].strip()
            owner_addr = hex(((int(owner_addr)&0xFFFFFFFFFFFFFFFF) & (~0x07)))
            owner_addr = str(owner_addr).strip('L')
            if not crash.valid_kernel_ptr(owner_addr):
                continue

        owner_pid = crash_inst.cmd('task_struct.pid  %s'%(owner_addr)).strip()
        if len(owner_pid) <= 0 or owner_pid.find('pid =') < 0:
            continue
        owner_pid = owner_pid.split('=')[-1].strip()

        if owner_pid not in figure['mutex'][mutex]['owner_task']:
            owner_name = crash_inst.cmd('bt %s'%(owner_pid)).strip()
            if len(owner_name) <= 0 or owner_name.find('COMMAND') < 0:
                continue
            owner_name = owner_name.split('COMMAND:')[-1].strip().splitlines()[0].strip('\"')
            figure['mutex'][mutex]['owner_task'][owner_pid] = owner_name

    if len(list(figure['mutex'])) == 0:
        print( "not found mutex handling!\n")
        return

    print( "\n--------------------mutex--------------------")
    for mutex in figure['mutex']:
        print( "mutex: %-20s %-20s"%(figure['mutex'][mutex]['name'], mutex))
        for owner in figure['mutex'][mutex]['owner_task']:
            print( "    mutex owner   task: %-10s %-20s"%(owner, figure['mutex'][mutex]['owner_task'][owner]))
        for waiting in figure['mutex'][mutex]['waiting_task']:
            print( "    mutex waiting task: %-10s %-20s"%(waiting, figure['mutex'][mutex]['waiting_task'][waiting]))
        print( "")
    deadlock_check(figure)

def main():
    sn = ''
    data = {}
    figure = {}
    mutex_check(sn, data, figure)

if __name__ == "__main__":
    main()
