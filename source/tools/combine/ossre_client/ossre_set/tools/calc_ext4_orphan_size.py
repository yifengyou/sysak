# -*- coding: utf-8 -*-
# @Author: lichen

import os
import sys
import time
import subprocess
import re

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

if sys.path[0].find('tools') > 0:
    sys.path.append("%s/../"%(sys.path[0]))
else:
    sys.path.append("%s/tools"%(sys.path[0]))
import collect_data
import crash

def query(sn, data):
    ret = {}
    ret['return'] = False
    ret['solution'] = []
    hotfix = ''

    journal_offset = int(6)
    version = collect_data.get_kernel_version(sn, data)
    if '4.9' in version:
        journal_offset = int(5)

    crash_inst = collect_data.get_live_crash(sn, data)
    crash_inst.cmd("mod -s jbd2")
    crash_inst.cmd("mod -s ext4")
    jbd2 = crash_inst.cmd('ps | grep jbd2/')
    if len(jbd2) <= 0 or jbd2.find("jbd2/") < 0:
        print( __name__,':',ret)
        return ret
    jbd2 = jbd2.splitlines()
    for task in jbd2:
        pid = task.strip().split()[0]
        btf = crash_inst.cmd("bt -f %s"%(pid))
        if len(btf) <= 0 or btf.find("jbd2") < 0:
            continue
        btf = btf.splitlines()
        stacks = []
        matched = 0
        for line in btf:
            if line.find("kthread at") > 0:
                break
            if matched:
                stacks.append(line)
                continue
            if line.find("kjournald2 at") > 0:
                matched = 1
                continue
        if len(stacks) < (journal_offset+1)/2:
            continue
        line = stacks[-((journal_offset+1)/2)]
        line = line.strip().split()[(journal_offset%2)+1]
        j_dev = crash_inst.cmd("struct journal_t.j_dev %s -x"%(line))
        if len(j_dev) <= 0 or j_dev.find("j_dev") < 0:
            continue
        j_dev = j_dev.strip().split("=")[1].strip()
        if not crash.valid_kernel_ptr(j_dev):
            continue
        j_devname = crash_inst.cmd("struct journal_t.j_devname %s -x"%(line))
        if len(j_devname) > 0 and j_devname.find("j_devname") >= 0:
            j_devname = j_devname.strip().split("=")[1].strip()[1:-1]
            j_devname = j_devname.split("\\0")[0]
        else:
            j_devname = "jbd2/%s"%(pid)
        bd_super = crash_inst.cmd("struct block_device.bd_super %s -x"%(j_dev))
        if len(bd_super) <= 0 or bd_super.find("bd_super") < 0:
            continue
        bd_super = bd_super.strip().split("=")[1].strip()
        if not crash.valid_kernel_ptr(bd_super):
            continue
        s_fs_info = crash_inst.cmd("struct super_block.s_fs_info %s -x"%(bd_super))
        if len(s_fs_info) <= 0 or s_fs_info.find("s_fs_info") < 0:
            continue
        s_fs_info = s_fs_info.strip().split("=")[1].strip()
        if not crash.valid_kernel_ptr(s_fs_info):
            continue
        s_orphan = crash_inst.cmd("struct ext4_sb_info.s_orphan %s -x"%(s_fs_info))
        if len(s_orphan) <= 0 or s_orphan.find("s_orphan") < 0:
            continue
        s_orphan = s_orphan.splitlines()
        next = ''
        prev = ''
        for item in s_orphan:
            item = item.strip()
            if item.find("next") >= 0:
                next = crash.extract_kernel_ptr(item)
            elif item.find("prev") >= 0:
                prev = crash.extract_kernel_ptr(item)
        if len(next) <= 0 or len(prev) <= 0:
            continue
        next = int(next,16)
        prev = int(prev,16)
        if next == prev:
            continue
        offset = crash_inst.cmd("struct ext4_inode_info -xo | grep i_orphan")
        if len(offset) <= 0 and offset.find("i_orphan") > 0:
            continue
        offset = int(offset.strip().split()[0][1:-1],16)
        next = hex(next-offset)[:-1]
        disksizes = crash_inst.cmd("list ext4_inode_info.i_orphan -s ext4_inode_info.i_disksize -h %s | grep i_disksize"%(next))
        if len(disksizes) <= 0 or disksizes.find('i_disksize') < 0:
            continue
        disksizes = disksizes.splitlines()
        total_size = 0
        for disksize in disksizes:
            disksize = disksize.strip().split("=")[1].strip()
            total_size += int(disksize)

        ret['return'] = True
        ret['solution'].append('%s orphan inodes total size %s'%(j_devname,total_size))

    print( __name__,':',ret)
    return ret

def main():
    sn = ''
    data = {}
    query(sn, data)

if __name__ == "__main__":
    main()
