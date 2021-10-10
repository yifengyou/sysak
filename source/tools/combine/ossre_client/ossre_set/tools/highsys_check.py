# -*- coding: utf-8 -*-
# @Author: shiyan

from subprocess import *
import os, fcntl, re, sys
from time import sleep
import fcntl
import perf
import importlib
import json

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
sys.path.append("%s/../rules"%(os.path.dirname(os.path.abspath(__file__))))
import crash
import collect_data

def main():
    sn = ''
    data = {}
    sys_sum = ''
    figure = {}
    figure['perf'] = {}
    figure['pidstat'] = {}
    figure['optimizing'] = {}
    figure['optimizing']['result_num'] = 0
    figure['optimizing']['cause'] = {}

    rets = {}
    rets['issue_result'] = {}
    ret = {}
    ret['return'] = False
    ret['solution'] = {}
    all_matched = {}

    tmp_perf_cpu_1 = []
    tmp_perf_cpu_2 = []
    tmp_perf_cpu_3 = []
    real_perf_cpu = []

    print ("开始扫描已知问题！")
    for subdir, dirs, files in os.walk("%s/../rules"%(sys.path[0])):
        for file in files:
            filepath = subdir + os.sep + file
            if os.path.isfile(filepath) and file.endswith('.py') and (
                file.startswith('HIGHSYS_')):
                fixup_mod = file[:-3]
                try:
                    mod = importlib.import_module(fixup_mod)
                    ret = mod.query(sn, data)
                    rets['issue_result'][fixup_mod] = {}
                    rets['issue_result'][fixup_mod] = ret
                    if ret['return']:
                        if all_matched.get('online') is None:
                            all_matched['online'] = {}
                        if all_matched['online'].get(file) is None:
                            all_matched['online'][file] = []
                        all_matched['online'][file].append(ret['solution'])
                except Exception as e:
                    print( '%s Exception!'%(fixup_mod),e)
                    pass
    if len(list(all_matched)) > 0:
        for i in all_matched:
            sys_sum += "\n匹配到已知sys高的问题:\n%s\n"%(json.dumps(all_matched[i],ensure_ascii=False))

    perf.get_mpstat_30sys_cpu(tmp_perf_cpu_1)
    sleep(0.3)
    perf.get_mpstat_30sys_cpu(tmp_perf_cpu_2)
    sleep(0.3)
    perf.get_mpstat_30sys_cpu(tmp_perf_cpu_3)
    if len(tmp_perf_cpu_1) > 0 and len(tmp_perf_cpu_2) > 0 and len(tmp_perf_cpu_3) > 0:
        for i in range(len(tmp_perf_cpu_1)):
            if tmp_perf_cpu_1[i] in tmp_perf_cpu_2 and tmp_perf_cpu_1[i] in tmp_perf_cpu_3:
                real_perf_cpu.append(tmp_perf_cpu_1[i])
    print ("\n经3次采样, 发现sys高于30%%的cpu列表: %s"%real_perf_cpu)

    tmp_perf_task_1 = []
    tmp_perf_task_2 = []
    tmp_perf_task_3 = []
    real_perf_task = []

    perf.get_pidstat_30sys_task(tmp_perf_task_1)
    sleep(0.3)
    perf.get_pidstat_30sys_task(tmp_perf_task_2)
    sleep(0.3)
    perf.get_pidstat_30sys_task(tmp_perf_task_3)
    if len(tmp_perf_task_1) > 0 and len(tmp_perf_task_2) > 0 and len(tmp_perf_task_3) > 0:
        for i in range(len(tmp_perf_task_1)):
            if tmp_perf_task_1[i] in tmp_perf_task_2 and tmp_perf_task_1[i] in tmp_perf_task_3:
                real_perf_task.append(tmp_perf_task_1[i])
    print ("\n经3次采样, 发现sys高于30%%的进程pid列表: %s"%real_perf_task)

    confirm = 'n'
    if len(real_perf_cpu) > 0 or len(real_perf_task) > 0:
        if sys.version[0] == '2':
            confirm = raw_input("\n是否使用perf辅助诊断，请输入y/n:\n")
        else:
            confirm = input("\n是否使用perf辅助诊断，请输入y/n:\n")
        if (confirm != 'y') and (confirm != 'n'):
            if sys.version[0] == '2':
                confirm = raw_input("输入错误，请再次输入y/n:\n")
            else:
                confirm = input("输入错误，请再次输入y/n:\n")
            if (confirm != 'y') and (confirm != 'n'):
                print ("输入错误，退出诊断！\n")
                return

    if confirm == 'y':
        try:
            if len(real_perf_cpu) > 0:
                for i in range(len(real_perf_cpu)):
                    perf.perf_cpu(real_perf_cpu[i], figure)

            if len(real_perf_task) > 0:
                for i in range(len(real_perf_task)):
                    perf.perf_task(real_perf_task[i], figure)
            if 'issue' in figure['perf']:
                if len(list(figure['perf']['issue'])) > 0:
                    for i in range(len(list(figure['perf']['issue']))):
                        figure['optimizing']['result_num'] += 1
                        result_num = figure['optimizing']['result_num']
                        summary = "当前sys高原因%s: %s\n"%(result_num, figure['perf']['issue'][i])
                        figure['optimizing']['cause'][result_num] = summary
            if figure['optimizing']['result_num'] > 0:
                for i in range(figure['optimizing']['result_num']):
                    sys_sum += figure['optimizing']['cause'][i+1]
            else:
                print ("未匹配到热点函数有关的已知问题，请分析热点函数代码逻辑")
            if len(sys_sum) > 0:
                print (sys_sum)

        except:
            print ("perf诊断失败!")
            pass
    else:
        if len(sys_sum) > 0:
            print (sys_sum)
        print ("退出诊断！")

if __name__ == "__main__":
    main()
