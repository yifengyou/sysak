#ifndef PING_H
#define PING_H

#include "pt/Packet.hpp"
#include "common/common.h"
#include <linux/filter.h>
#include <linux/icmp.h>
#include <signal.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_MAX 4096

#define CHECK(expr, str, code)                                                                                                                                                                         \
	do {                                                                                                                                                                                               \
	if (expr)                                                                                                                                                                                      \
		throw ping_exception{str, code};                                                                                                                                                           \
	} while (0)

namespace pingtrace
{
struct Ping {
	int fd;

  public:
	Ping(int accept_type, int special_opt, int timeo_usec = -1)
	{
		int filter = ~accept_type;
		int ret;
		uint8_t val = 1;

		fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		CHECK(fd < 0, "do you have a capability to create raw socket?\n", fd);

		ret = setsockopt(fd, SOL_RAW, ICMP_FILTER, &filter, sizeof(filter));
		CHECK(ret, "setsockopt ICMP_FILTER failed\n", ret);
		if (timeo_usec != -1) {
			ret = set_timeout(timeo_usec);
			CHECK(ret, "setsockopt SO_RCVTIMEO failed\n", ret);
		}
	}
	~Ping() { close(fd); }

	int set_timeout(int timeo_usec)
	{
		struct timeval tv;

		if (timeo_usec != -1) {
			tv.tv_sec = timeo_usec / 1000000;
			tv.tv_usec = timeo_usec % 1000000;
		} else {
			tv.tv_sec = 0;
			tv.tv_usec = 0;
		}
		return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
	}

	void send(const struct sockaddr_in *dest, PingTracePacket &pkt)
	{
		sendto(fd, pkt.icmp_header(), pkt.icmp_size(), 0, (struct sockaddr *)dest, sizeof(*dest));
	}

	int recv(char *buf, int buf_len, struct sockaddr_in *from)
	{
		socklen_t fromlen = sizeof(*from);

		return recvfrom(fd, buf, buf_len, 0, (struct sockaddr *)from, &fromlen);
	}

	void set_bpf_filter(uint32_t id)
	{
		uint16_t icmp_id = id & 0xffff;

		struct sock_filter insns[] = {
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0),		       /* Skip IP header due BSD. */
			BPF_STMT(BPF_LD | BPF_H | BPF_IND, 4),		       /* Load icmp echo ident */
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(icmp_id), 0, 1), /* Ours? */
			BPF_STMT(BPF_RET | BPF_K, ~0U),			       /* Yes, it passes. */
			BPF_STMT(BPF_LD | BPF_B | BPF_IND, 0),		       /* Load icmp type */
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ICMP_ECHO, 1, 0),      /* Echo? */
			BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFF),		       /* No. It passes. */
			BPF_STMT(BPF_RET | BPF_K, 0)			       /* Echo with wrong ident. Reject. */
		};
		struct sock_fprog filter = {sizeof insns / sizeof(insns[0]), insns};
		int ret;

		ret = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
		CHECK(ret, "failed to load bpf filter", ret);
	}
};

class PingTrace
{
  protected:
	uint32_t id;
	static bool stop;

  public:
	static void set_signal_callback(uint64_t timeout)
	{
		struct sigaction sact;

		sact.sa_handler = [](int) { PingTrace::stop = true; };
		sact.sa_flags = 0;
		sigaction(SIGINT, &sact, NULL);
		if (timeout != -1) {
			sigaction(SIGALRM, &sact, NULL);
			alarm(timeout);
		}
	}
	PingTrace()
	{
		stop = false;

		srand((unsigned)time(NULL));
		id = rand();
	}
	virtual ~PingTrace() {}

	bool recv_and_parse(Ping &ping, PingTracePacket &pkt, const sockaddr_in &remote_ip, bool &timeout)
	{
		sockaddr_in from;
		int ret;

		timeout = false;
		ret = pkt.buf_size = ping.recv((char *)(pkt.buf), pkt.buf_cap, &from);
		if (ret < 0) {
			timeout = (errno == ETIMEDOUT || errno == EAGAIN);
			return false;
		}
		if (from.sin_addr.s_addr != remote_ip.sin_addr.s_addr)
			return false;
		if (!pkt.unpack(ICMP_ECHOREPLY))
			return false;
		if (pkt.id() != id)
			return false;
		return true;
	}
};
bool PingTrace::stop = false;

}; // namespace pingtrace

#endif