#!/usr/bin/python
# -*- coding: UTF-8 -*-

import ctypes as ct
import math
from subprocess import Popen, PIPE
from time import sleep

stars_max = 38
log2_dist_max = 64

dist={}

def _stars(val, val_max, width):
    i = 0
    text = ""
    while (1):
        if (i > (width * val / val_max) - 1) or (i > width - 1):
            break
        text += "*"
        i += 1
    if val > val_max:
        text = text[:-1] + "+"
    return text

def print_log2_hist(dist, val_type="value"):
    """print_log2_hist(type=value)
    Prints a table as a log2 histogram. The table must be stored as
    log2. The type argument is optional, and is a column header.
    """
    global stars_max
    global log2_dist_max
    idx_max = -1
    val_max = 0
    for i in range(1, log2_dist_max + 1):
        try:
            val = dist[i]
            if (val > 0):
                idx_max = i
            if (val > val_max):
                val_max = val
        except:
            break
    if idx_max > 0:
        print("     %-15s : count     distribution" % val_type);
    for i in range(1, idx_max + 1):
        low = (1 << i) >> 1
        high = (1 << i) - 1
        if (low == high):
            low -= 1
        try:
            val = dist[i]
            print("%8d -> %-8d : %-8d |%-*s|" % (low, high, val,
                stars_max, _stars(val, val_max, stars_max)))
        except:
            break

if __name__ == '__main__':

    print("Sampling run queue length... Hit Ctrl-C to end.")

    exiting = 0

    dist = {}

    for i in range(1, log2_dist_max + 1):
        #dist[ct.c_int(i)] = 0
        dist[i] = 0

    while (1):
        try:
            # sleep 10ms
            sleep(0.01)

            comm = "cat /proc/sched_debug  | grep 'R'  | wc -l"
            process = Popen(comm,stdout=PIPE, stderr=PIPE, shell=True)

            stdout, stderr = process.communicate()
            
            if stderr:
                continue

            # excluding the currently running task
            value = int(stdout) - 1
            dist[value.bit_length()] += 1

        except KeyboardInterrupt:
            exiting = 1

        if exiting:
            print_log2_hist(dist, "runqlen")
            exit()