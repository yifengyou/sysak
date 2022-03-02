#!/usr/bin/python2
#coding:utf-8

import re
import os.path

uname_command = "uname -r"

kernel_version = ""
kversion_alinux3 = "5.10.60-9.al8.x86_64"
alinux3_etc_sysctl = "/etc/sysctl.d/50-aliyun.conf"
dict_paraments = {'kernel.unprivileged_bpf_disabled': 1}

file_max = "/proc/sys/fs/file-max"
nr_open = "/proc/sys/fs/nr_open" 
etc_security_limit = "/etc/security/limits.conf"

pagecache_dirty_bytes = "/proc/sys/vm/dirty_bytes"
pagecache_dirty_ratio = "/proc/sys/vm/dirty_ratio"
pagecache_bk_dirty_bytes = "/proc/sys/vm/dirty_background_bytes"
pagecache_bk_dirty_ratio = "/proc/sys/vm/dirty_background_ratio"
meminfo = "/proc/meminfo"

syslog_conf_dir = "/etc/syslog-ng"

def exectue_cmd(command):
    command=command.replace("\n", "")
    command_fd = os.popen(command, "r")
    ret = command_fd.read()
    command_fd.close()
    ret.strip('\n')
    return ret

def get_kernelversion():
    global kernel_version
    kernel_version = exectue_cmd(uname_command)

def check_pagecache_config():
    pagecache_watermask = 0
    mem_total_val = 0
    pagecache_bk_watermask = 0

    dirty_bytes_fd = open(pagecache_dirty_bytes,"r")
    dirty_bytes_val = dirty_bytes_fd.read(30)
    dirty_bytes_fd.close()

    dirty_ratio_fd = open(pagecache_dirty_ratio,"r")
    dirty_ratio_val = dirty_ratio_fd.read(30)
    dirty_ratio_fd.close()

    bk_dirty_bytes_fd = open(pagecache_bk_dirty_bytes,"r")
    bk_dirty_bytes_val = bk_dirty_bytes_fd.read(30)
    bk_dirty_bytes_fd.close()

    bk_dirty_ratio_fd = open(pagecache_bk_dirty_ratio,"r")
    bk_dirty_ratio_val = bk_dirty_ratio_fd.read(30)
    bk_dirty_ratio_fd.close()

    meminfo_fd= open(meminfo,"r")
    for line in meminfo_fd.readlines():
        mem_total= re.search(r'MemTotal: *(\d+) kB', line, re.I)
        if mem_total:
            mem_total_val = mem_total.group(1)
            pagecache_watermask = int(mem_total_val)*1024*20/100

    if dirty_bytes_val:
        if int(dirty_ratio_val) < 20:
            print("vm.dirty_ratio=%s 低于20，可能造成pagecache频繁回写，io拥塞" %(dirty_ratio_val))
    else:
        if dirty_bytes_val <= pagecache_watermask:
            print("vm.dirty_bytes=%s 低于20%Mem，可能造成pagecache频繁回写，io拥塞" %(dirty_bytes_val))
    meminfo_fd.close()
 
    pagecache_bk_watermask = int(mem_total_val)*1024*10/100

    if bk_dirty_bytes_val:
        if int(bk_dirty_ratio_val) < 10:
            print("vm.dirty_background_bytes=%s 低于10，可能造成pagecache后台频繁回写，io拥塞" %(bk_dirty_ratio_val))
    else:
        if bk_dirty_bytes_val <= pagecache_bk_watermask:
            print("vm.dirty_bytes=%s 低于10%Mem，可能造成pagecache后台频繁回写，io拥塞" %(bk_dirty_bytes_val))
    return


def check_etc_config():
    if kernel_version == kversion_alinux3:
        alinux3_etc_fd = open(alinux3_etc_sysctl,"r")
        for line in alinux3_etc_fd.readlines():
            match_parament= re.search( r'kernel.unprivileged_bpf_disabled = (\d+)', line, re.I)
            if match_parament:           
                for parament in dict_paraments.keys():
                    if dict_paraments[parament] == match_parament.group(1):
                        print("kernel.unprivileged_bpf_disabled应该配置成1")
        alinux3_etc_fd.close()

    syslog_conf_cmd = 'grep "/var/log/messages" -rn /etc/syslog-ng |wc -l'
    syslog_conf_num = exectue_cmd(syslog_conf_cmd)
    if syslog_conf_num.strip('\n') != "1":
        print("syslog重复配置/var/log/messages，可能导致重复打印日志!")
    return

def check_file_config():
    file_max_fd = open(file_max,"r")
    nr_open_fd = open(nr_open,"r")
    file_max_val = file_max_fd.read(30)
    nr_open_val = nr_open_fd.read(30)

    if int(file_max_val) <= int(nr_open_val):
        print("fs.file-max应该大于fs.nr_open")
    file_max_fd.close()
    nr_open_fd.close()

    etc_security_limit_fd = open(etc_security_limit,"r")
    for line in etc_security_limit_fd.readlines():
        match_parament = re.search( r'\* soft nofile (\d+)', line, re.I)
        if match_parament:
            if int(match_parament.group(1)) > int(nr_open_val):
                print("soft nofile不能超过fs.nr_open" )
    etc_security_limit_fd.close()

def overcommit_check():
    overcommit_memory_cmd = 'sysctl -n vm.overcommit_memory'
    overcommit_memory = exectue_cmd(overcommit_memory_cmd).strip('\n')
    overcommit_kbytes_cmd = 'sysctl -n vm.overcommit_kbytes'
    overcommit_kbytes = exectue_cmd(overcommit_kbytes_cmd).strip('\n')
    overcommit_ratio_cmd = 'sysctl -n vm.overcommit_ratio'
    overcommit_ratio = exectue_cmd(overcommit_ratio_cmd).strip('\n')

    meminfo_fd= open(meminfo,"r")
    for line in meminfo_fd.readlines():
        if "CommitLimit" in line:
            CommitLimit = line
        if "Committed_AS" in line:
            Committed_AS = line

    if overcommit_memory == "0":
        print("vm.overcommit_memory = %s" %(overcommit_memory)) 
        print("vm.overcommit_kbytes和vm.overcommit_ratio设置的值不会生效，只要当前系统还有可用内存，即可继续分配虚拟地址区间。")
    elif overcommit_memory == "1":
        print("vm.overcommit_memory = %s" %(overcommit_memory)) 
        print("vm.overcommit_kbytes和vm.overcommit_ratio设置的值不会生效，不会受CommitLimit限制，始终可分配虚拟地址。")
    else:
        print("vm.overcommit_kbytes = %s," %(overcommit_kbytes))
        print("vm.overcommit_ratio = %s," %(overcommit_ratio))
        print(CommitLimit + Committed_AS)

def main():
    get_kernelversion()
    check_file_config()
    check_etc_config()
    check_pagecache_config()
    overcommit_check()

if __name__ == '__main__':
    main()
