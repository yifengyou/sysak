# -*- coding: utf-8 -*-
# @Author: weichen.chen
# @CreateTime: 2020-12-24 16:46:43
# @ModifyTime: 2020-12-24 16:46:43
# @Description: print the vring of specified virtio-net device

from __future__ import print_function
import os
import sys
import argparse

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
import collect_data
from crash import struct_get_member,struct_get_size

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

NET_DEV_ALIGN = 32

def ALIGN(x, a):
    return (((x) + (a) - 1) & ~((a) - 1))

# This function returns the net_device of specified device.
#
# The output of 'net' is like:
#    NET_DEVICE     NAME   IP ADDRESS(ES)
# ffff88083fbae000  lo     127.0.0.1
# ffff88081c49e000  eth0   172.16.116.144
def get_net_device(crash_inst, device):
    devs = crash_inst.cmd("net").strip()
    for dev in devs.splitlines()[1:]: # remove the title line
        if device in dev:
            return dev.split()[0]
    return None


def process_one_virtqueue(crash_inst, vring_virtqueue, data):
    name = struct_get_member(crash_inst.cmd("struct vring_virtqueue.vq.name %s" % vring_virtqueue))
    num = int(struct_get_member(crash_inst.cmd("struct vring_virtqueue.vring.num %s" % vring_virtqueue)))
    desc_states = struct_get_member(crash_inst.cmd("struct vring_virtqueue.desc_state %s" % vring_virtqueue))
    print("[Virtqueue %s (%s)]: num %d" % (name, vring_virtqueue, num))

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

    if name.startswith("input") and avail_idx == used_idx and last_used_idx < used_idx:
        print("[WARN] Is this input queue working? There is some data in queue but backend haven't kick us yet.")


def process_one_device(crash_inst, device, data):
    net_device = get_net_device(crash_inst, device)
    if not net_device:
        print("ERROR: %s device doesn't exist." % device)

    net_device_size = struct_get_size(crash_inst.cmd("struct net_device"))
    virtnet_info = str(hex(int(net_device, 16) + ALIGN(int(net_device_size), NET_DEV_ALIGN))).rstrip("L")
    send_queue = struct_get_member(crash_inst.cmd("struct virtnet_info.sq %s" % virtnet_info))
    receive_queue = struct_get_member(crash_inst.cmd("struct virtnet_info.rq %s" % virtnet_info))
    max_queue_pairs = int(struct_get_member(crash_inst.cmd("struct virtnet_info.max_queue_pairs %s" % virtnet_info)))
    curr_queue_pairs = int(struct_get_member(crash_inst.cmd("struct virtnet_info.curr_queue_pairs %s" % virtnet_info)))
    print("[%s]" % device)
    print("num_vqs %d" % curr_queue_pairs)

    if curr_queue_pairs < max_queue_pairs:
        print("[WARN] NIC multi-queue not enable, current queue num: %s, max queue num: %s" % (curr_queue_pairs, max_queue_pairs))

    for i in range(curr_queue_pairs):
        receive_virtqueue = struct_get_member(crash_inst.cmd("gdb p ((struct receive_queue*)%s)[%d] | grep vq" % (receive_queue, i)))
        receive_vring_virtqueue = receive_virtqueue
        process_one_virtqueue(crash_inst, receive_vring_virtqueue, data)
        send_virtqueue = struct_get_member(crash_inst.cmd("gdb p ((struct send_queue*)%s)[%d] | grep vq" % (send_queue, i)))
        send_vring_virtqueue = send_virtqueue
        process_one_virtqueue(crash_inst, send_vring_virtqueue, data)

def main():
    sn = ''
    data = {}

    # arguments
    examples = """examples:
            ./virtio_net_print_vring.py eth0        # Print vring of virtio-net device.
    """
    parser = argparse.ArgumentParser(
            description="Print vring of virtio-net device.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=examples)
    parser.add_argument("device", nargs=1, help="name of the virtio-net device, such as 'eth0'")
    args = parser.parse_args()

    print("Opening crash...", end='')
    crash_inst = collect_data.get_live_crash(sn, data)
    print("done")

    # We need load modules like virtio, virtio_ring, virtio_net, etc.
    # The default search path of 'mod -S' is '/usr/lib/modules/', while we need load
    # modules from debuginfo.
    collect_data.get_kernel_version(sn, data)
    ver = data['version'].split()[2]
    crash_inst.cmd("mod -S /usr/lib/debug/lib/modules/%s/kernel/" % ver)

    process_one_device(crash_inst, args.device[0], data)

if __name__ == "__main__":
    main()
