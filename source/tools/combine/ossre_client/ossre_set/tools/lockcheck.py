# -*- coding: utf-8 -*-
# @Author: shiyan

import os
import sys
import datetime,time
import subprocess
import re
import socket
import json
import loadcheck,semcheck,rwsemcheck,mutexcheck,alidiagnose,perf
from time import sleep

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
import utils
import collect_data

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

def main():
    sn = ''
    data = {}
    figure = {}
    lock_ret = { }
    lock_ret["has_lock"] = 0
    lock_ret["summary"] = ""
    version = collect_data.get_kernel_version(sn, data)
    summary = ""
    figure['optimizing'] = {}
    figure['optimizing']['result_num'] = 0
    figure['optimizing']['cause'] = {}
    try:

        mutexcheck.mutex_check(sn, data, figure)
        if len(list(figure['mutex'])) > 0:
            lock_ret["has_lock"] = 1
            mutex_waiting_num = 0;
            for mutex in figure['mutex']:
                mutex_waiting_num += len(list(figure['mutex'][mutex]['waiting_task']))
            #if mutex_waiting_num >= figure['sched']['load_1']/3:
            #figure['optimizing']['result_num'] += 1
            #result_num = figure['optimizing']['result_num']
            summary += "当前有 %s 个任务在等mutex\n"%( mutex_waiting_num)
                #figure['optimizing']['cause'][result_num] = summary
            #summary += ( "\n-----mutex-----\n")
            for mutex in figure['mutex']:
                summary += ( "mutex: %-20s %-20s\n"%(figure['mutex'][mutex]['name'], mutex))
                for owner in figure['mutex'][mutex]['owner_task']:
                    summary += ( "    mutex owner   task: %-10s %-20s\n"%(owner, figure['mutex'][mutex]['owner_task'][owner]))
                num = 0
                for waiting in figure['mutex'][mutex]['waiting_task']:
                    num += 1
                    summary += ( "    mutex waiting task: %-10s %-20s\n"%(waiting, figure['mutex'][mutex]['waiting_task'][waiting]))
                    if num >= 10:
                        summary += "......\n"
                        break
                summary += ( "\n")

        semcheck.sem_check(sn, data, figure)
        if len(list(figure['sem'])) > 0:
            lock_ret["has_lock"] = 1
            sem_waiting_num = 0;
            for sem in figure['sem']:
                sem_waiting_num += len(list(figure['sem'][sem]['waiting_task']))
            #if sem_waiting_num >= figure['sched']['load_1']/3:
            #figure['optimizing']['result_num'] += 1
            #result_num = figure['optimizing']['result_num']
            summary += "当前有 %s 个任务在等semaphore\n"%( sem_waiting_num)
                #figure['optimizing']['cause'][result_num] = summary
            #summary += ( "\n-----semaphore-----\n")
            for sem in figure['sem']:
                summary += ( "sem: %-20s %-20s waiting num: %s\n"%(figure['sem'][sem]['name'], sem, len(figure['sem'][sem]['waiting_task'])))
                num = 0
                for waiting in figure['sem'][sem]['waiting_task']:
                    num += 1
                    summary += ( "    waiting task: %-10s %-20s\n"%(waiting, figure['sem'][sem]['waiting_task'][waiting]))
                    if num >= 10:
                        summary += "......\n"
                        break
                summary += ( "\n")

        rwsemcheck.rwsem_check(sn, data, figure)
        if len(list(figure['rwsem'])) > 0:
            lock_ret["has_lock"] = 1
            rwsem_waiting_num = 0;
            for rwsem in figure['rwsem']:
                rwsem_waiting_num += len(list(figure['rwsem'][rwsem]['waiting_task']))
            #if rwsem_waiting_num >= figure['sched']['load_1']/3:
            #figure['optimizing']['result_num'] += 1
            #result_num = figure['optimizing']['result_num']
            summary += "当前有 %s 个任务在等rwsemaphore\n"%( rwsem_waiting_num)

            #summary += ( "\n-----rw_semaphore-----\n")
            for rwsem in figure['rwsem']:
                summary += ( "rwsem: %-20s %-20s waiting num: %s\n"%(figure['rwsem'][rwsem]['name'], rwsem, len(figure['rwsem'][rwsem]['waiting_task'])))
                num = 0
                for waiting in figure['rwsem'][rwsem]['waiting_task']:
                    num += 1
                    summary += ( "    waiting(for %5s) task: %-10s %-20s\n"%(figure['rwsem'][rwsem]['rw'], waiting, figure['rwsem'][rwsem]['waiting_task'][waiting]))
                    if num >= 10:
                        summary += "......\n"
                        break

                if '4.9' in version or '4.19' in version:
                    if 'owner' in figure['rwsem'][rwsem]:
                        if figure['rwsem'][rwsem]['owner']['rorw'] == 1:
                            summary += ( "    owner task is reading!\n")
                        else:
                            summary += ( "    owner task is writing!\n")
                            if 'pid' in figure['rwsem'][rwsem]['owner'] and 'name' in figure['rwsem'][rwsem]['owner']:
                                summary += ( "    owner task: %s    %s\n"%(figure['rwsem'][rwsem]['owner']['name'],figure['rwsem'][rwsem]['owner']['pid']))

                summary += ( "\n")
                #figure['optimizing']['cause'][result_num] = summary
        print summary
        lock_ret["summary"] = summary
        f = open("/tmp/lockcheck.log", "w+")
        f.write(json.dumps(lock_ret,ensure_ascii=False))
        f.close()
    except:
        lock_ret["summary"] += "%s\n解析异常！\n"%summary
        f = open("/tmp/lockcheck.log", "w+")
        f.write(json.dumps(lock_ret,ensure_ascii=False))
        f.close()
        import traceback
        traceback.print_exc()
        print "lockcheck exception!"
    #query(sn, data)

if __name__ == "__main__":
    if os.path.isfile("/tmp/lockcheck.log"):
        cmd = 'echo "" > /tmp/lockcheck.log'
        output = os.popen(cmd)
        #a = output.read()
        output.close()
        print "/tmp/lockcheck.log exist"
    else:
        print "/tmp/lockcheck.log not exist"
    main()
            
