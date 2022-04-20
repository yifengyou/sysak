#!/usr/bin/python2

import os
import sys
import getopt

memThres = 102400 
socketCheck = False 
socketThres = 2000
socketLeak = 500

def os_cmd(cmd):
    ret = os.popen(cmd).read().split("\n")
    return ret

def get_tcp_mem():
    ret = os_cmd(" cat /proc/net/sockstat")
    for line in ret:
        if line.find("TCP:") == -1:
            continue
        tcp_mem = line.strip().split(" ")
        return int(tcp_mem[-1])*4

def get_local_ip(line):
    if line.find(".") == -1:
        return "unknow"
    ip = line.split(" ")
    for tmp in ip:
        if tmp.find(".") != -1:
            return tmp.strip()
    return "unkonw"

def get_task(line):
    if line.find("users") == -1:
        return get_local_ip(line)
    start = line.find("(")
    if start == -1:
        return "unknow"
    end = line.find(")")
    if end == -1:
        return "unknow"
    task = line[start+3:end].strip()
    if len(task) < 2:
        return "unknow"
    task = task.split(",")
    comm = task[0][:-1]
    pid = task[1].split("=")[1]
    return comm + ":" + pid

def tcp_mem_check():
    ret = os_cmd("ss -tnapm")
    tcp_mem = get_tcp_mem()
    memTask = {}
    tx_mem = 0
    rx_mem = 0
    idx = 0
    for idx in range(len(ret)):
        line = ret[idx]
        #print("line start")
        #print(line)
        #print("line end")
        if line.find("skmem") == -1:
            continue
        prev_line = ret[idx -1]
        task = get_task(prev_line)
        skmem = line.strip().split("(")[1]
        skmem = skmem[:-1].split(",")
        rx = int(skmem[0][1:])
        tx = int(skmem[2][1:])
        rx_mem += rx
        tx_mem += tx
        if rx + tx < 1024:
            continue
        if task not in memTask.keys():
            memTask[task] = 0
        memTask[task] += (rx + tx)

    total = (rx_mem + tx_mem)/1024          
    print("tx_queue {}K rx_queue {}K queue_total {}K tcp_mem {}K".format(tx_mem/1024, rx_mem/1024, total, tcp_mem))
    if tcp_mem > memThres and tcp_mem > total*1.5:
        print("tcp memleak tcp_mem:{}K tx_rx queue:{}K".format(tcp_mem, total))
        print("\n")
        print("task hold memory:")
        for task, value in memTask.items():
            print("task {} mem {}K".format(task, value/1024))
    print("\n")
    return total,tcp_mem

def _socket_inode_x(inodes,protocol,idx):
    cmd = "cat /proc/net/" + protocol + " "
    ret = os_cmd(cmd)
    skip = 0
    
    for line in ret:
        tmp = idx
        if skip == 0:
            skip = 1
            continue
        line = line.strip()
        inode = line.split(" ")
        if len(inode) < abs(idx) + 1:
            continue
        #print("line : {}".format(line))
        #print("list : {}".format(inode))

        """ fix idx for unix socket """
        if (idx == -2) and (line.find("/") == -1):
            tmp = -1

        #print("inode = {} idx {} ".format(inode[tmp], idx))
        if inode[tmp]:
            inodes.append(inode[tmp])
    #print("\n") 
    return inodes
 
def socket_inode_1(inodes):
    _socket_inode_x(inodes, "netlink", -1) 
    _socket_inode_x(inodes, "packet", -1) 

def socket_inode_2(inodes):
    return _socket_inode_x(inodes, "unix", -2) 

def socket_inode_4(inodes):
    _socket_inode_x(inodes, "udp", -4)
    _socket_inode_x(inodes, "udp6", -4)
    _socket_inode_x(inodes, "udplite", -4)
    _socket_inode_x(inodes, "udplite6", -4)
    _socket_inode_x(inodes, "raw", -4)
    _socket_inode_x(inodes, "raw6", -4)

def socket_inode_8(inodes):
    _socket_inode_x(inodes, "tcp", -8)
    _socket_inode_x(inodes, "tcp6", -8)

def socket_inode_get(inodes):
    socket_inode_1(inodes)
    socket_inode_2(inodes)
    socket_inode_4(inodes)
    socket_inode_8(inodes)


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass
    try:
        import unicodedata
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass
    return False

def get_comm(proc):
    cmd = "cat " +proc+"/comm"
    ret = os.popen(cmd).read().strip()
    return ret

def scan_all_proc(inodes):
    root = "/proc/"
    allProcInode = []
    global socketThres
    global socketLeak
    try:
        for proc in os.listdir(root):
            if not os.path.exists(root + proc):
                continue
            if not is_number(proc):
                continue
            procName = root + proc + "/fd/"
            taskInfo = {}
            taskInfo["task"] = ""
            taskInfo["inode"] = []
            inodeNum = 0
            inodeLeakNum = 0
            try:
                for fd in os.listdir(procName):
                    inodeInfo = {}
                    if not os.path.exists(procName+fd):
                        continue
                    link = os.readlink(procName+fd)
                    if link.find("socket:[") == -1:
                        continue
                    inode = link.strip().split("[")
                    if len(inode) < 2:
                        continue
                    inodeNum += 1
                    inode = inode[1][:-1].strip()
                    #print("fd {} link {} inode {}".format(procName+fd, link, inode))
                    if inode not in inodes:
                        inodeInfo["fd"] = procName+fd
                        inodeInfo["link"] = link
                        inodeInfo["inode"] = inode
                        taskInfo["inode"].append(inodeInfo)
                        inodeLeakNum += 1
                if inodeNum >= socketThres or inodeLeakNum > socketLeak:
                    taskInfo["task"] = get_comm(root+proc)
                    taskInfo["pid"] = proc
                    taskInfo["num"] = inodeNum
                    taskInfo["numleak"] = inodeLeakNum
                    allProcInode.append(taskInfo)
            except Exception:
                import traceback
                traceback.print_exc()
                pass
    except Exception :
        import traceback
        traceback.print_exc()
        pass
    #print("inode leak ={}".format(allProcInode))
    return allProcInode

def socket_leak_check():
    inodes = []
    newLeak = []
    global socketCheck

    if socketCheck == False:
        return newLeak
    socket_inode_get(inodes)
    taskLeak = scan_all_proc(inodes)
    """ Try again"""
    inodes = []
    socket_inode_get(inodes)
    newLeak = []
    for taskInfo in taskLeak:
        if taskInfo["num"] > socketThres:
            newLeak.append(taskInfo)
            continue
        inodeNum = 0
        for inodeInfo in taskInfo["inode"]:
            if not os.path.exists(inodeInfo["fd"]):
                continue       
            link = os.readlink(inodeInfo["fd"])
            if link != inodeInfo["link"]:
                continue
            if inodeInfo["inode"] not in inodes:
                inodeNum += 1
        if inodeNum > socketLeak:
            newLeak.append(taskInfo)
    return newLeak

def get_args(argv):
    global memThres
    global socketCheck
    global socketThres
    global socketLeak

    try:
        opts, args = getopt.getopt(argv,"hm:t:sl:")
    except getopt.GetoptError:
        print 'tcp memory and socket leak check'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print("tcp memory and socket leak check")
            print("default enable for tcp memmory check")
            print("-s:enable socket leak check")
            print("-t:threshold value for open socket ,default is 2000") 
            print("-l:leak threshold for shutdown socket ,default is 500")
            sys.exit()
        elif opt in ("-m"):
            memThres = int(arg) * 1024
        elif opt in ("-s"):
            socketCheck = True
        elif opt in ("-t"):
            socketThres = int(arg)
        elif opt in ("-l"):
            socketLeak = int(arg)
        else:
            print("error args options")
    
if __name__ == "__main__":
    inodes = []
    get_args(sys.argv[1:])
    tcp_mem_check()
    leak = socket_leak_check()
    for taskInfo in leak:
        print("{}:{} socketNum {} socketLeakNum {}".format(taskInfo["task"], taskInfo["pid"], taskInfo["num"], taskInfo["numleak"])) 
