# -*- coding: utf-8 -*-
# @Author: fuqiu

from subprocess import *
import os, fcntl, re
from time import sleep

def valid_kernel_ptr(addr):
    addr = addr.strip()
    if re.match(r"0x[0-9a-f]+$",addr) is None:
        return False
    else:
        return True

def extract_kernel_ptr(addr):
    addr = addr.strip()
    pattern = r".*(0x[0-9a-f]+).*"
    m = re.match(pattern, addr)
    if m is not None:
        return m.group(1)
    else:
        return ''
        
def struct_get_size(string):
    return string.splitlines()[-1].split()[-1]

def struct_get_member(string):
    return string.split()[-1].strip(',')

def filter_all_btf_by_addr(bta, addr, func=''):
    if type(bta) == type(''):
                bta = bta.splitlines()
    pidcts = {}
    calltrace = []
    pid = ''
    for eachline in bta:
        if "PID:" in eachline:
            eachline = eachline.strip()
            calltrace = []
            calltrace.append(eachline)
            pid = eachline.strip().split()[1]
        elif len(eachline.strip()) == 0:
            bt = []
            matched = 0
            if len(calltrace) > 0:
                for line in calltrace:
                    if len(func) > 0 and func in line:
                        calltrace = []
                        continue
                    if addr in line:
                        matched = 1
                    if line.strip().startswith('#'):
                        bt.append(line)
                if matched:
                    pidcts[pid] = bt
                calltrace = []
        else:
            if len(calltrace) > 0:
                calltrace.append(eachline)
    return pidcts

def filter_all_bt_by_func(bta, func):
    if type(bta) == type(''):
        bta = bta.splitlines()
    pidcts = {}
    calltrace = []
    pid = ''
    for eachline in bta:
        if "PID:" in eachline:
            eachline = eachline.strip()
            calltrace = []
            calltrace.append(eachline)
            pid = eachline.strip().split()[1]
        elif len(eachline.strip()) == 0:
            matched = 0
            if len(calltrace) > 0:
                for line in calltrace:
                    if func in line:
                        matched = 1
                if matched:
                    pidcts[pid] = calltrace
                calltrace = []
        else:
            if len(calltrace) > 0:
                calltrace.append(eachline)
    return pidcts

class Crash:
    __crash_inst = None

    def live_attach(self):
        if os.geteuid() != 0:
            raise Exception("Live crash must run as root!")

        run_offline = os.environ.get('run_offline')
        if run_offline is None:
            run_offline = 0
        else:
            run_offline = int(run_offline)

        try:
            self.__crash_inst = Popen('crash'.split(), shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        except OSError as err:
            raise Exception("Can't execute crash, please yum install crash.<" + repr(err) +">")
        
        while True:
            line =  self.__crash_inst.stdout.readline()
            line = line.decode('ascii')
            if(line.startswith( '       STATE:' )):
            #if line.find('STATE: ')>=0:
                break;
            if(line.find("Permission denied")>0):
                raise Exception("Permission denied:" + line)
            if(line.find("cannot find booted kernel")>0):
                raise Exception("vmlinux not found, please yum install debuginfo")

    def vmcore_attach(self, vmcore, vmlinux):
        try:
            cmd = 'crash -x %s %s'%(vmcore, vmlinux)
            self.__crash_inst = Popen(cmd.split(), shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        except OSError as err:
            raise Exception("Can't execute crash, please yum install crash.<" + repr(err) +">")

        while True:
            line =  self.__crash_inst.stdout.readline()
            line = line.decode('ascii')
            if(line.startswith( '       STATE:' )):
                break;
            if(line.find("Permission denied")>0):
                raise Exception("Permission denied:" + line)
            if(line.find("cannot find booted kernel")>0):
                raise Exception("vmlinux not found, please yun install debuginfo")
            if(line.find("No such file or directory")>0):
                raise Exception("No such file or directory:" + line)
            if(line.find("read error")>0):
                raise Exception("read error" + line)
            if(line.find("unable to read header")>0):
                raise Exception("unable to read header" + line)
            if(line.find("do not match")>0):
                raise Exception("do not match" + line)
            if(line.find("Failed to read")>0):
                raise Exception("Failed to read" + line)

    def cmd(self, cmd):
        output = ""
        cmd = cmd+ " | sed \'$a\<<Crash buffer end>>\'\n"
        cmd=cmd.encode('ascii')
        #self.__crash_inst.stdin.write(cmd+ " | sed \'$a\<<Crash buffer end>>\'\n")
        self.__crash_inst.stdin.write(cmd)
        while True:
            line =  self.__crash_inst.stdout.readline()
            line = line.decode('ascii') 
            if(line.startswith("<<Crash buffer end>>")):
                break;
            output += line
        return output

    # Used for cmds with huge outputs, like foreach/ps...
    def partcmd(self, cmd, new=1):
        ret = {"need_continue":0,"output":""}
        num_line = 0
        if new == 1:
            cmd = cmd+ " | sed \'$a\<<Crash buffer end>>\'\n"
            cmd=cmd.encode('ascii')
            #self.__crash_inst.stdin.write(cmd+ " | sed \'$a\<<Crash buffer end>>\'\n")
            self.__crash_inst.stdin.write(cmd)
        while True:
            line =  self.__crash_inst.stdout.readline()
            line = line.decode('ascii')
            if(line.startswith("<<Crash buffer end>>")):
                ret["need_continue"] = 0
                break;
            ret["output"] += line
            num_line += 1
            if num_line > 1000:
                ret["need_continue"] = 1
                break
        return ret

    def __init__(self, core=None, vmlinux=None):
        if ( core == None):
            self.live_attach()
        elif (core != None and vmlinux != None):
            self.vmcore_attach(core, vmlinux)

    def close(self):
        self.__crash_inst.close()

