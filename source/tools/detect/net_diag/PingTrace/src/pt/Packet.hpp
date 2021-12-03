#ifndef PINGTRACE_PACKET_H
#define PINGTRACE_PACKET_H

#include "bpf/map_define.h"
#include "common/common.h"
#include "common/util.hpp"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/icmp.h>
#include <stdlib.h>
#include <string.h>

#define PINGTRACE_CODE_MAGIC 1
#define PINGTRACE_HDR_MAGIC 0x7ace

#define PINGTRACE_IP_HLEN 20

namespace pingtrace
{
struct PingTracePacket {
	pingtrace_pkt *buf;
	int buf_cap;
	int buf_size;

  public:
	PingTracePacket() : buf(nullptr), buf_cap(0), buf_size(0) {}
	~PingTracePacket()
	{
		if (!buf)
			return;
		free(buf);
	}
	PingTracePacket(PingTracePacket &&rhs)
	{
		this->buf = rhs.buf;
		this->buf_cap = rhs.buf_cap;
		this->buf_size = rhs.buf_size;
	}

	PingTracePacket &operator=(PingTracePacket &&rhs)
	{
		if (this == &rhs)
			return *this;
		if (buf)
			free(buf);
		this->buf = rhs.buf;
		this->buf_cap = rhs.buf_cap;
		this->buf_size = rhs.buf_size;
		return *this;
	}

  private:
	uint16_t do_checksum(const uint8_t *start, uint32_t len)
	{
		uint16_t i;
		const uint16_t *wptr = (uint16_t *)start;
		uint32_t csum = 0;

		for (i = 1; i < len; i += 2)
			csum += (uint32_t)(*(wptr++));
		if (len & 1)
			csum += *(uint8_t *)wptr;
		if (csum >> 16)
			csum = (csum & 0xFFFF) + (csum >> 16);
		return ~csum;
	}

	pingtrace_timestamp build_send_ts(uint64_t node_id)
	{
		pingtrace_timestamp ts;

		ts.machine_id = node_id;
		ts.function_id = P_L_TX_USER;
		ts.ts = util::get_time();
		return ts;
	}

  public:
	int init(uint32_t max_entry_num)
	{
		buf_cap = sizeof(pingtrace_pkt) + max_entry_num * sizeof(pingtrace_timestamp);
		buf_size = buf_cap;
		buf = (pingtrace_pkt *)malloc(buf_cap);
		if (!buf)
			return -ENOMEM;
		return 0;
	}

	void set_icmp_type(uint8_t type) { buf->icmp.type = type; }
	uint32_t seq() { return be32toh(buf->hdr.seq); }
	uint32_t id() { return be32toh(buf->hdr.id); }
	uint16_t flags() { return ntohs(buf->hdr.flags); }
	void set_flags(uint16_t flags) { buf->hdr.flags = htons(flags); }
	unsigned entry_num() { return buf->hdr.num; }
	unsigned max_entry_num() { return (buf_cap - sizeof(pingtrace_pkt)) / sizeof(pingtrace_timestamp); }
	bool valid() { return buf; }

	pingtrace_timestamp get_timestamp(int idx)
	{
		pingtrace_timestamp ts, *p;

		p = &buf->entries[idx];
		ts.function_id = ntohs(p->function_id);
		ts.ifindex = ntohl(p->ifindex);
		ts.ns_id = ntohl(p->ns_id);
		ts.user_id = ntohs(p->user_id);
		ts.ts = ntohl(p->ts);
		return ts;
	}
	icmp *icmp_header() { return &buf->icmp; }
	int size() { return buf_size; }
	int icmp_size() { return buf_size - sizeof(ip); }

	void init_header(uint32_t seq, uint32_t id, uint32_t reserve_entry_num)
	{
		uint16_t icmp_id = id & 0xffff;
		memset(buf, 0, buf_size);
		buf->icmp.type = ICMP_ECHO;
		buf->icmp.code = PINGTRACE_CODE_MAGIC;
		buf->icmp.checksum = 0;
		buf->icmp.id = htons(icmp_id);
		buf->icmp.seq = htons(seq & 0xffff);
		buf->hdr.version = 0;
		buf->hdr.num = reserve_entry_num;
		buf->hdr.flags = htons(0);
		buf->hdr.magic = htons(PINGTRACE_HDR_MAGIC);
		buf->hdr.seq = htobe32(seq);
		buf->hdr.id = htobe32(id);
	}

	void add_timestamp(const pingtrace_map_entry &entry, uint16_t user_id)
	{
		pingtrace_timestamp *p = &buf->entries[buf->hdr.num];
		if (buf->hdr.num < max_entry_num()) {
			p->function_id = htons(entry.function_id);
			p->ts = htonl(util::ns_truncate(entry.ns));
			p->ns_id = htonl(entry.net_inum);
			p->ifindex = htonl(entry.ifindex);
			p->user_id = htons(user_id);
			buf->hdr.num++;
		}
	}

	void add_timestamp(const pingtrace_timestamp &ts)
	{
		pingtrace_timestamp *p = &buf->entries[buf->hdr.num];
		if (buf->hdr.num < max_entry_num()) {
			p->machine_id = htobe64(ts.machine_id);
			p->function_id = htons(ts.function_id);
			p->ts = htonl(ts.ts);
			buf->hdr.num++;
		}
	}

	void update_checksum()
	{
		buf->icmp.checksum = 0;
		buf->icmp.checksum = do_checksum((uint8_t *)&(buf->icmp),
										  buf_size - (uint32_t)sizeof(ip));
	}

	void pack(uint32_t seq, uint32_t id, uint32_t reserve_entry_num)
	{
		init_header(seq, id, reserve_entry_num);
		update_checksum();
	}

	bool unpack(uint8_t icmp_type)
	{
		ip *ip = &(buf->ip);
		icmp *icmp = &(buf->icmp);
		pingtrace_hdr *hdr = &(buf->hdr);

		if (buf_size < sizeof(pingtrace_pkt))
			return false;

		if (ip->version != 4)
			return false;
		if ((ip->hlen << 2) != PINGTRACE_IP_HLEN)
			return false;
		if (ip->protocol != IPPROTO_ICMP)
			return false;
		if (icmp->type != icmp_type || icmp->code != PINGTRACE_CODE_MAGIC)
			return false;
		if (hdr->version != 0 || ntohs(hdr->magic) != PINGTRACE_HDR_MAGIC)
			return false;
		return true;
	}
};
}; // namespace pingtrace

#endif