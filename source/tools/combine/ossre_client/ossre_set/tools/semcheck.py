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

def sem_check(sn, data, figure):
    global live_crash
    un_task = []
    un_task_pid = []
    figure['sem'] = {}
    print( "semaphore checking ......")

    version = collect_data.get_kernel_version(sn, data)
    if '3.10' in version:
        sem_begin = '__down_common at'
        sem_end = '__down at'
        sem_lock_offset = -7
    elif '4.9' in version:
        sem_begin = '__down at'
        sem_end = 'down at'
        sem_lock_offset = -5
    elif '4.19' in version:
        sem_begin = '__down at'
        sem_end = 'down at'
        sem_lock_offset = -2
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
        if (task_bt_f.find('__down_common') < 0) and (task_bt_f.find('__down') < 0):
            continue
        task_bt_f = task_bt_f.splitlines()
        task_bt_F = task_bt_F.splitlines()
        reach_sem = 0
        bt_addr_f = []

        for line in task_bt_f:
            line = line.strip()
            if line.find(sem_begin) >= 0:
                reach_sem = 1
            elif line.find(sem_end) >= 0:
                break
            elif reach_sem == 1:
                index = line.index(':')
                line = line[index+1:].strip().split()
                for addr in line:
                    bt_addr_f.append(addr)
                continue

        if len(bt_addr_f) < 7:
            continue
        sem = bt_addr_f[sem_lock_offset]
        if sem not in figure['sem']:
            figure['sem'][sem] = {}
            figure['sem'][sem]['waiting_task'] = {}

        reach_sem = 0
        bt_addr_F = []
        for line in task_bt_F:
            line = line.strip()
            if line.find(sem_begin) >= 0:
                reach_sem = 1
            elif line.find(sem_end) >= 0:
                break
            elif reach_sem == 1:
                index = line.index(':')
                line = line[index+1:].strip().split()
                for addr in line:
                    bt_addr_F.append(addr)
                continue

        if len(bt_addr_F) < 7:
            continue
        sem_name = bt_addr_F[sem_lock_offset]

        figure['sem'][sem]['name'] = sem_name

        waiting_name = crash_inst.cmd('bt %s'%(pid)).strip()
        if len(waiting_name) <= 0 or waiting_name.find('COMMAND') < 0:
            continue
        waiting_name = waiting_name.split('COMMAND:')[-1].strip().splitlines()[0].strip('\"')

        figure['sem'][sem]['waiting_task'][pid] = waiting_name

    if len(list(figure['sem'])) == 0:
        print( "not found semaphore handling!\n")
        return

    print( "\n--------------------semaphore--------------------")
    for sem in figure['sem']:
        print( "sem: %-20s %-20s waiting num: %s"%(figure['sem'][sem]['name'], sem, len(figure['sem'][sem]['waiting_task'])))
        for waiting in figure['sem'][sem]['waiting_task']:
            print( "    waiting task: %-10s %-20s"%(waiting, figure['sem'][sem]['waiting_task'][waiting]))
        print( "")

def main():
    sn = ''
    data = {}
    figure = {}
    sem_check(sn, data, figure)

if __name__ == "__main__":
    main()
