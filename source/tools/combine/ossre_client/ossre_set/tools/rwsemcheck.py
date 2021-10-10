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

def rwsem_check(sn, data, figure):
    global live_crash
    un_task = []
    un_task_pid = []
    figure['rwsem'] = {}
    print( "rwsem checking ......")

    version = collect_data.get_kernel_version(sn, data)
    if '3.10' in version:
        read_begin = 'rwsem_down_read_failed at'
        read_end = 'call_rwsem_down_read_failed at'
        read_lock_offset = -6
        write_begin = 'rwsem_down_write_failed at'
        write_end = 'call_rwsem_down_write_failed at'
        write_lock_offset = -7
    elif '4.9' in version:
        read_begin = 'rwsem_down_read_failed at'
        read_end = 'call_rwsem_down_read_failed at'
        read_lock_offset = -7
        write_begin = 'rwsem_down_write_failed at'
        write_end = 'call_rwsem_down_write_failed at'
        write_lock_offset = -7
    elif '4.19' in version:
        read_begin = 'rwsem_down_read_failed at'
        read_end = 'call_rwsem_down_read_failed at'
        read_lock_offset = -10
        write_begin = 'rwsem_down_write_failed at'
        write_end = 'call_rwsem_down_write_failed at'
        write_lock_offset = -9
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
        if (task_bt_f.find('rwsem_down_read_failed') < 0) and (task_bt_f.find('rwsem_down_write_failed') < 0):
            continue
        task_bt_f = task_bt_f.splitlines()
        task_bt_F = task_bt_F.splitlines()
        reach_rwsem = 0
        rorw = 0
        bt_addr_f = []

        for line in task_bt_f:
            line = line.strip()
            #print line
            if rorw == 0 and line.find(read_begin) >= 0:
                #print line
                reach_rwsem = 1
                rorw = 1
            elif rorw  == 1 and line.find(read_end) >= 0:
                #print line
                break
            elif reach_rwsem == 1 and rorw == 1:
                #print line
                index = line.index(':')
                line = line[index+1:].strip().split()
                for addr in line:
                    bt_addr_f.append(addr)
                continue

            if rorw == 0 and line.find(write_begin) >= 0:
                reach_rwsem = 1
                rorw = 2
            elif rorw  == 2 and line.find(write_end) >= 0:
                break
            elif reach_rwsem == 1 and rorw == 2:
                index = line.index(':')
                line = line[index+1:].strip().split()
                for addr in line:
                    bt_addr_f.append(addr)

        if len(bt_addr_f) < 7:
            continue
        if rorw == 1:
            rwsem = bt_addr_f[read_lock_offset]
        if rorw == 2:
            rwsem = bt_addr_f[write_lock_offset]
        if rwsem not in figure['rwsem']:
            figure['rwsem'][rwsem] = {}
            #figure['rwsem'][rwsem]['rw'] = {}
            figure['rwsem'][rwsem]['waiting_task'] = {}
            if rorw == 1:
                figure['rwsem'][rwsem]['rw'] = "read"
            elif rorw == 2:
                figure['rwsem'][rwsem]['rw'] = "write"

        reach_rwsem = 0
        rorw = 0
        bt_addr_F = []
        for line in task_bt_F:
            line = line.strip()
            if rorw == 0 and line.find(read_begin) >= 0:
                reach_rwsem = 1
                rorw = 1
            elif rorw == 1 and line.find(read_end) >= 0:
                break
            elif reach_rwsem == 1 and rorw == 1:
                index = line.index(':')
                line = line[index+1:].strip().split()
                for addr in line:
                    bt_addr_F.append(addr)
                continue

            if rorw == 0 and line.find(write_begin) >= 0:
                reach_rwsem = 1
                rorw = 2
            elif rorw == 2 and line.find(write_end) >= 0:
                break
            elif reach_rwsem == 1 and rorw == 2:
                index = line.index(':')
                line = line[index+1:].strip().split()
                for addr in line:
                    bt_addr_F.append(addr)

        if len(bt_addr_F) < 7:
            continue
        if rorw  == 1:
            rwsem_name = bt_addr_F[read_lock_offset]
        if rorw  == 2:
            rwsem_name = bt_addr_F[write_lock_offset]

        figure['rwsem'][rwsem]['name'] = rwsem_name

        waiting_name = crash_inst.cmd('bt %s'%(pid)).strip()
        if len(waiting_name) <= 0 or waiting_name.find('COMMAND') < 0:
            continue
        waiting_name = waiting_name.split('COMMAND:')[-1].strip().splitlines()[0].strip('\"')

        figure['rwsem'][rwsem]['waiting_task'][pid] = waiting_name

    if len(list(figure['rwsem'])) == 0:
        print( "not found rwsem handling!\n")
        return

    if '4.9' in version or '4.19' in version:
        for rwsem in figure['rwsem']:
            rwsem_owner = crash_inst.cmd('struct rw_semaphore.owner  %s'%rwsem)
            if len(rwsem_owner) <= 0 or rwsem_owner.find('owner') < 0:
                continue
            owner_addr = rwsem_owner.split('=')[-1].strip()
            figure['rwsem'][rwsem]['owner'] = {}
            figure['rwsem'][rwsem]['owner']['address'] = owner_addr
            if owner_addr == '0x1':
                figure['rwsem'][rwsem]['owner']['rorw'] = 1
            else:
                figure['rwsem'][rwsem]['owner']['rorw'] = 2
                if not crash.valid_kernel_ptr(owner_addr):
                    continue
                owner_pid = crash_inst.cmd('task_struct.pid  %s'%(owner_addr)).strip()
                if len(owner_pid) <= 0 or owner_pid.find('pid =') < 0:
                    continue
                owner_pid = owner_pid.split('=')[-1].strip()
                owner_name = crash_inst.cmd('bt %s'%(owner_pid)).strip()
                if len(owner_name) <= 0 or owner_name.find('COMMAND') < 0:
                    continue
                owner_name = owner_name.split('COMMAND:')[-1].strip().splitlines()[0].strip('\"')
                figure['rwsem'][rwsem]['owner']['pid'] = owner_pid
                figure['rwsem'][rwsem]['owner']['name'] = owner_name

    print( "\n--------------------rw_semaphore--------------------")
    for rwsem in figure['rwsem']:
        print( "rwsem: %-20s %-20s waiting num: %s"%(figure['rwsem'][rwsem]['name'], rwsem, len(figure['rwsem'][rwsem]['waiting_task'])))
        for waiting in figure['rwsem'][rwsem]['waiting_task']:
            print( "    waiting(for %5s) task: %-10s %-20s"%(figure['rwsem'][rwsem]['rw'], waiting, figure['rwsem'][rwsem]['waiting_task'][waiting]))

        if '4.9' in version or '4.19' in version:
            if 'owner' in figure['rwsem'][rwsem]:
                if figure['rwsem'][rwsem]['owner']['rorw'] == 1:
                    print( "    owner task is reading!")
                else:
                    print( "    owner task is writing!")
                    if 'pid' in figure['rwsem'][rwsem]['owner'] and 'name' in figure['rwsem'][rwsem]['owner']:
                        print( "    owner task: %s    %s"%(figure['rwsem'][rwsem]['owner']['name'],figure['rwsem'][rwsem]['owner']['pid']))

        print( "")

def main():
    sn = ''
    data = {}
    figure = {}
    rwsem_check(sn, data, figure)

if __name__ == "__main__":
    main()
