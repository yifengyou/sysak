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

reload(sys)
sys.setdefaultencoding('utf8')


# This function returns the request_queue of specified device.
#
# The output of 'dev -d' is like:
# MAJOR GENDISK            NAME       REQUEST_QUEUE      TOTAL ASYNC  SYNC   DRV
#   253 ffff88ac36917000   vda        ffff88ac35e68000       0     0     0 N/A(MQ)
def get_request_queue(crash_inst, device):
    devs = crash_inst.cmd("dev -d").strip()
    for dev in devs.splitlines()[1:]: # remove the title line
        if device in dev:
            return dev.split()[3]
    return None


def process_one_virtqueue(crash_inst, vring_virtqueue, data):
    index = struct_get_member(crash_inst.cmd("struct vring_virtqueue.vq.index %s" % vring_virtqueue))
    num = int(struct_get_member(crash_inst.cmd("struct vring_virtqueue.vring.num %s" % vring_virtqueue)))
    desc_states = struct_get_member(crash_inst.cmd("struct vring_virtqueue.desc_state %s" % vring_virtqueue))
    print("[Virtqueue %s (%s)]: num %d" % (index, vring_virtqueue, num))

    num_free = int(struct_get_member(crash_inst.cmd("struct vring_virtqueue.vq.num_free %s" % vring_virtqueue)))
    free_head = int(struct_get_member(crash_inst.cmd("struct vring_virtqueue.free_head %s" % vring_virtqueue)))
    print("Descriptor Table: num_free %d, free_head %d" % (num_free, free_head))

    avail_ring = struct_get_member(crash_inst.cmd("struct vring_virtqueue.vring.avail %s" % vring_virtqueue))
    avail_idx = int(struct_get_member(crash_inst.cmd("struct vring_avail.idx %s" % avail_ring)))
    avail_flags = struct_get_member(crash_inst.cmd("struct vring_avail.flags %s" % avail_ring))
    print("Available Ring: flags %s, avail_idx %d" % (avail_flags, avail_idx))

    used_ring = struct_get_member(crash_inst.cmd("struct vring_virtqueue.vring.used %s" % vring_virtqueue))
    used_idx = int(struct_get_member(crash_inst.cmd("struct vring_used.idx %s" % used_ring)))
    last_used_idx = int(struct_get_member(crash_inst.cmd("struct vring_virtqueue.last_used_idx %s" % vring_virtqueue)))
    used_flags = struct_get_member(crash_inst.cmd("struct vring_used.flags %s" % used_ring))
    used_elem_ring = struct_get_member(crash_inst.cmd("struct vring_used.ring %s" % used_ring))
    print("Used Ring: flags %s, used_idx %d, last_used_idx %d" % (used_flags, used_idx, last_used_idx))

    if last_used_idx < used_idx:
        print("USED_INDEX DESC_TABLE_INDEX REQUEST")

    while last_used_idx < used_idx:
        index_in_used_ring = last_used_idx & (num - 1)
        last_used_idx += 1
        index_in_desc_table = int(struct_get_member(crash_inst.cmd("gdb p (((struct vring_used_elem*)%s)[%d]) | grep id" % (used_elem_ring, index_in_used_ring))))
        virtblk_req = struct_get_member(crash_inst.cmd("gdb p (((struct vring_desc_state*)%s)[%d]) | grep data" % (desc_states, index_in_desc_table)))
        # struct virtblk_req is just allocated after struct request
        request = struct_get_member(crash_inst.cmd("gdb p (((struct request*)%s) - 1)" % virtblk_req))
        print("%10d %16d %s" % (index_in_used_ring, index_in_desc_table, request))


def process_one_device(crash_inst, device, data):
    queue = get_request_queue(crash_inst, device)
    if not queue:
        print("ERROR: %s device doesn't exist." % device)

    virtio_blk = struct_get_member(crash_inst.cmd("struct request_queue.queuedata %s" % queue))
    num_vqs = int(struct_get_member(crash_inst.cmd("struct virtio_blk.num_vqs %s" % virtio_blk)))
    vqs = struct_get_member(crash_inst.cmd("struct virtio_blk.vqs %s" % virtio_blk))

    print("[%s]" % device)
    print("num_vqs %d" % num_vqs)
    for i in range(num_vqs):
        virtqueue = struct_get_member(crash_inst.cmd("gdb p (((struct virtio_blk_vq**)%s)[%d]) | grep vq" % (vqs, i)))
        vring_virtqueue = virtqueue
        process_one_virtqueue(crash_inst, vring_virtqueue, data)

def main():
    sn = ''
    data = {}

    # arguments
    examples = """examples:
            .virtio_blk_print_vring/.py vdc        # Print vring of virtio-blk device.
    """
    parser = argparse.ArgumentParser(
            description="Print vring of virtio-blk device.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=examples)
    parser.add_argument("device", nargs=1, help="name of the virtio-blk device, such as 'vda'")
    args = parser.parse_args()

    print("Opening crash...", end='')
    crash_inst = collect_data.get_live_crash(sn, data)
    print("done")

    # We need load modules like virtio, virtio_ring, virtio_blk, etc.
    # The default search path of 'mod -S' is '/usr/lib/modules/', while we need load
    # modules from debuginfo.
    collect_data.get_kernel_version(sn, data)
    ver = data['version'].split()[2]
    crash_inst.cmd("mod -S /usr/lib/debug/lib/modules/%s/kernel/" % ver)

    process_one_device(crash_inst, args.device[0], data)

if __name__ == "__main__":
    main()
