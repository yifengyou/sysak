# -*- coding: utf-8 -*-
# @Author: feixu

from __future__ import print_function
import os
import sys
import argparse

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
import collect_data
from crash import struct_get_member

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')


# This function returns hang request queues.
#
# Retuns a list of all hang request queues, each is a dictionary in format of
# ('name':NAME, 'total':TOTAL, 'queue':REQUEST_QUEUE)
#
# The output of 'dev -d' is like:
# MAJOR GENDISK            NAME       REQUEST_QUEUE      TOTAL ASYNC  SYNC   DRV
#   253 ffff88ac36917000   vda        ffff88ac35e68000       0     0     0 N/A(MQ)
def find_hang_request_queue(crash_inst, device):
    queues = []
    devs = crash_inst.cmd("dev -d").strip().splitlines()

    # remove the title line
    for index, dev in enumerate(devs):
        if 'REQUEST_QUEUE' in dev:
            break
    devs = devs[index:]

    for dev in devs:
        if not device or (device and device in dev):
            fields = dev.split()
            if fields[4] != '0':
                queues.append({'name':fields[2], 'total':int(fields[4]), 'queue':'0x'+fields[3]})
    return queues


def get_all_set_bit(bitset):
    bits = []
    i = 0
    while (bitset != 0):
        if bitset & 0x1:
            bits.append(i)
        i += 1
        bitset = bitset >> 1
    return bits

# Calculate the uptime in seconds.
def get_uptime(crash_inst):
    day = hour = minu = sec = 0
    # The output is like:
    # 'UPTIME: 10 days, 14:14:39' or 'UPTIME: 00:02:30'
    uptime = crash_inst.cmd("sys | grep UPTIME")
    time = uptime.split()[-1].split(':')

    if 'days' in uptime:
        day = int(uptime.split()[1])
    hour = int(time[0])
    minu = int(time[1])
    sec  = int(time[2])

    return day * 24 * 3600 + hour * 3600 + minu * 60 + sec


def print_request(crash_inst, request, data):
    version = data['version']
    threshold = data['threshold']
    cmd_flags = int(struct_get_member(crash_inst.cmd("struct request.cmd_flags %s" % request)))
    op = flag = ''

    if '3.10' in version:
        if cmd_flags & (1<<7) : op = 'DISCARD'
        else: op = 'WRITE' if cmd_flags & 0x1 else 'READ'
        if cmd_flags & (1<<4): flag = 'SYNC'

    elif '4.9' in version:
        opstr = ['READ', 'WRITE', 'DISCARD', 'SECURE_ERASE', 'WRITE_SAME', 'FLUSH']
        # high 3 bits used for identifying request direction and type
        opval = cmd_flags >> 61
        op = opstr[opval]
        if cmd_flags & (1<<3): flag = 'SYNC'

    elif '4.19' in version:
        opstr = ['READ', 'WRITE', 'FLUSH', 'DISCARD', 'ZONE_REPORT', 'SECURE_ERASE', 'ZONE_RESET',
                'WRITE_SAME', '', 'WRITE_ZEROES']
        # low 8 bits used for indentifying ops
        opval = cmd_flags & ((1<<8) - 1)
        op = opstr[opval]
        if cmd_flags & (1<<10): flag = 'SYNC'

    if flag:
        print("request %s: cmd_flags %x [%s|%s]" % (request, cmd_flags, op, flag))
    else:
        print("request %s: cmd_flags %x [%s]" % (request, cmd_flags, op))

    start_time_ns = struct_get_member(crash_inst.cmd("struct request.start_time_ns %s" % request))
    io_start_time_ns = struct_get_member(crash_inst.cmd("struct request.io_start_time_ns %s" % request))
    print(".start_time_ns=%s, .io_start_time_ns=%s, " % (start_time_ns, io_start_time_ns), end='')

    bio = struct_get_member(crash_inst.cmd("struct request.bio %s" % request))
    while bio != '0x0':
        print(".bio=%s, .sector=%s, .len=%s, " % (
            bio,
            struct_get_member(crash_inst.cmd("struct bio.bi_iter.bi_sector %s" % bio)),
            struct_get_member(crash_inst.cmd("struct bio.bi_iter.bi_size %s" % bio))), end='')

        bi_vcnt = struct_get_member(crash_inst.cmd("struct bio.bi_vcnt %s" % bio))
        bi_io_vec = struct_get_member(crash_inst.cmd("struct bio.bi_io_vec %s" % bio))
        bio_str = ".bio_pages: {"
        bio_vec_str = crash_inst.cmd("struct bio_vec -c %s %s" % (bi_vcnt, bi_io_vec)).strip().splitlines()
        for string in bio_vec_str:
            bio_str += string.strip()
            if string == '}': bio_str += ', '
        bio_str = bio_str[:-2] # remove trailing ', '
        bio_str += '}'
        print("%s" % bio_str, end='')

        bio = struct_get_member(crash_inst.cmd("struct bio.bi_next %s" % bio))

    print();print()
    
    if threshold and (data['current_time'] - int(start_time_ns)) > threshold:
        data['timeouts'] += 1


def process_one_hw_ctx(crash_inst, tagmap, index, data):
    nr_tags = int(struct_get_member(crash_inst.cmd("struct blk_mq_tags.nr_tags %s" % tagmap)))
    nr_reserved_tags = int(struct_get_member(crash_inst.cmd("struct blk_mq_tags.nr_reserved_tags %s" % tagmap)))
    base = 0
    tags = []

    # process reserved tag bitmap
    map_nr = int(struct_get_member(crash_inst.cmd("struct blk_mq_tags.breserved_tags.sb.map_nr %s" % tagmap)))
    words = struct_get_member(crash_inst.cmd("struct blk_mq_tags.breserved_tags.sb.map %s" % tagmap))

    # The output is like:
    # > struct sbitmap_word -c 4 0xffff88ac35d25b00
    # struct sbitmap_word {
    #      word = 0,
    #      depth = 32
    # }
    #
    # struct sbitmap_word {
    #      word = 3407872,
    #      depth = 32
    # }
    if map_nr != 0:
        bitmaps = crash_inst.cmd("struct sbitmap_word -c %d %s" % (map_nr, words))
        for line in bitmaps.splitlines():
            if 'depth =' in line:
                base += int(line.split()[-1])
            elif 'word =' in line:
                word = int(struct_get_member(line))
                tags += [bit+base for bit in get_all_set_bit(word) if bit+base < nr_reserved_tags]

    # process normal tag bitmap
    map_nr = int(struct_get_member(crash_inst.cmd("struct blk_mq_tags.bitmap_tags.sb.map_nr %s" % tagmap)))
    words = struct_get_member(crash_inst.cmd("struct blk_mq_tags.bitmap_tags.sb.map %s" % tagmap))

    if map_nr != 0:
        bitmaps = crash_inst.cmd("struct sbitmap_word -c %d %s" % (map_nr, words))
        for line in bitmaps.splitlines():
            if 'depth =' in line:
                base += int(line.split()[-1])
            elif 'word =' in line:
                word = int(struct_get_member(line))
                tags += [bit+base+nr_reserved_tags for bit in get_all_set_bit(word) if bit+base < nr_tags]
                
    
    print("[Hardware Queue %d]" % index)
    rqs = struct_get_member(crash_inst.cmd("struct blk_mq_tags.rqs %s" % tagmap))
    for tag in tags:
        request = struct_get_member(crash_inst.cmd("gdb p (((struct request**)%s)[%d])" % (rqs, tag)))
        print_request(crash_inst, request, data)
    return len(tags)


def process_one_queue(crash_inst, queue_info, data):
    num = 0
    data['timeouts'] = 0    # reset number of timeouted requests
    queue = queue_info['queue']
    nr_hw_queues = int(struct_get_member(crash_inst.cmd("struct request_queue.nr_hw_queues %s" % queue)))
    tagset = struct_get_member(crash_inst.cmd("struct request_queue.tag_set %s" % queue))
    tags = struct_get_member(crash_inst.cmd("struct blk_mq_tag_set.tags %s" % tagset))

    print("[%s] %d pending requests:" % (queue_info['name'], queue_info['total']))

    for i in range(nr_hw_queues):
        # Output of gdb is like:
        # >gdb p (((struct blk_mq_tags**)0xffff800352d8deb0)[0])
        # $3 = (struct blk_mq_tags *) 0xffff80035287d980
        tagmap = struct_get_member(crash_inst.cmd("gdb p (((struct blk_mq_tags**)%s)[%d])" % (tags, i)))
        num += process_one_hw_ctx(crash_inst, tagmap, i, data)

    if (num != queue_info['total']):
        print("ERROR: inconsisten number of pending requests %d vs %d" % (queue_info['total'], num))

    if data['threshold']:
        print("[%s] %d hang requests." % (queue_info['name'], data['timeouts']))
 

def main():
    sn = ''
    data = {}

    # arguments
    examples = """examples:
            ./blk_get_hang_request.py        # print all requests in request_queue
            ./blk_get_hang_request.py -d vdc # print all requests in request_queue of vdc
            ./blk_get_hang_request.py -t 5   # print all requests in request_queue, also inspect whether
                                               there's hang request given the timeout threshold in sec.
    """
    parser = argparse.ArgumentParser(
            description="Print hang requests of request queue.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=examples)
    parser.add_argument("-t", "--threshold", help="Timeout threshold of hang requests.")
    parser.add_argument("-d", "--device", help="Check specified device only.")
    args = parser.parse_args()
    threshold = int(args.threshold) * 1000000000 if args.threshold else 0

    print("Opening crash...", end='')
    crash_inst = collect_data.get_live_crash(sn, data)
    print("done")

    queues = find_hang_request_queue(crash_inst, args.device)

    collect_data.get_kernel_version(sn, data)
    data['current_time'] = get_uptime(crash_inst)
    data['threshold'] = threshold

    if queues:
        print("Current Time: %d s" % data['current_time'], end='')
    if args.threshold:
        print(", Threshold: %s s" % args.threshold)
    else:
        print()

    for queue_info in queues:
        process_one_queue(crash_inst, queue_info, data)

if __name__ == "__main__":
    main()
