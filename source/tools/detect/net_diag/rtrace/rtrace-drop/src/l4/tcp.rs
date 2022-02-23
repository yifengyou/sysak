use crate::base::{kernel_version_compare, RtraceDrop, RtraceDropAction};
use anyhow::Result;
use rtrace_parser::func::Func;
use rtrace_rs::bindings::*;
use std::boxed::Box;

#[derive(Default, Clone)]
pub struct Tcp {
    points: Vec<Box<dyn RtraceDrop>>,
}

impl RtraceDrop for Tcp {
    fn init(&mut self) -> Result<()> {
        self.points.push(Box::new(TcpConnRequest::default()));
        self.points.push(Box::new(Tcpv4SynRecvSock::default()));
        self.points.push(Box::new(TcpAddBacklog::default()));
        self.points.push(Box::new(SkbChecksumComplete::default()));
        Ok(())
    }

    fn get_name(&self) -> &str {
        "tcp"
    }

    fn get_subpoints(&self) -> Option<&Vec<Box<dyn RtraceDrop>>> {
        Some(&self.points)
    }
}

#[derive(Default, Clone)]
struct TcpConnRequest {}

impl RtraceDrop for TcpConnRequest {
    fn get_probe_string(&self) -> &str {
        r#"
[[function]]
name = "tcp_conn_request"
params = ["basic"]
exprs = ["sk.sk_ack_backlog", "sk.sk_max_ack_backlog", "((struct inet_connection_sock *)sk).icsk_accept_queue.qlen.counter"]
        "#
    }

    fn get_name(&self) -> &str {
        "tcp_conn_request"
    }

    fn get_status(&self) -> &str {
        "[Support]"
    }

    fn check_func(&mut self, _func: &Func, vals: &Vec<u64>) -> RtraceDropAction {
        // ((struct inet_connection_sock *)sk).icsk_accept_queue.qlen.counter > sk.sk_max_ack_backlog : syn queue overflow
        if vals[2] > vals[1] {
            return RtraceDropAction::Consume(format!(
                "Syn queue overflow: {} > {}",
                vals[2], vals[1]
            ));
        }
        // sk.sk_ack_backlog > sk.sk_max_ack_backlog : accept queue overflow
        if vals[0] > vals[1] {
            return RtraceDropAction::Consume(format!(
                "Accept queue overflow: {} > {}",
                vals[0], vals[1]
            ));
        }
        RtraceDropAction::Continue
    }
}
#[derive(Default, Clone)]
struct Tcpv4SynRecvSock {}
impl RtraceDrop for Tcpv4SynRecvSock {
    fn get_probe_string(&self) -> &str {
        r#"
[[function]]
name = "tcp_v4_syn_recv_sock"
params = ["basic"]
exprs = ["sk.sk_ack_backlog", "sk.sk_max_ack_backlog"]
        "#
    }

    fn get_name(&self) -> &str {
        "tcp_v4_syn_recv_sock"
    }

    fn get_status(&self) -> &str {
        "[Support]"
    }

    fn check_func(&mut self, func: &Func, vals: &Vec<u64>) -> RtraceDropAction {
        // sk.sk_ack_backlog > sk.sk_max_ack_backlog : accept queue overflow
        if vals[0] > vals[1] {
            return RtraceDropAction::Consume(format!(
                "Accept queue overflow: {} > {}",
                vals[0], vals[1]
            ));
        }
        RtraceDropAction::Continue
    }
}

#[derive(Default, Clone)]
struct TcpAddBacklog {
    headroom: u64,
}
impl RtraceDrop for TcpAddBacklog {
    fn init(&mut self) -> Result<()> {
        let res = kernel_version_compare(4, 19, 0);
        if res < 0 {
            self.headroom = 0;
        } else {
            self.headroom = 64 * 1024;
        }
        Ok(())
    }
    fn get_probe_string(&self) -> &str {
        r#"
[[function]]
name = "tcp_add_backlog"
params = ["basic"]
exprs = ["sk.sk_backlog.len", "sk.sk_backlog.rmem_alloc", "sk.sk_rcvbuf", "sk.sk_sndbuf"]
        "#
    }

    fn get_status(&self) -> &str {
        "[Support]"
    }

    fn check_func(&mut self, _func: &Func, vals: &Vec<u64>) -> RtraceDropAction {
        if vals[0] + vals[1] > vals[2] + vals[3] + self.headroom {
            return RtraceDropAction::Consume(format!(
                "Backlog queue overflow:
                    Judge Expression: sk_backlog.len + sk_backlog.rmem_alloc > sk_rcvbuf + sk_sndbuf + HEADROOM 
                    Actual Expression: {} + {} > {} + {} + {}
                ",
                vals[0], vals[1], vals[2], vals[3], self.headroom
            ));
        }
        RtraceDropAction::Continue
    }

    fn get_name(&self) -> &str {
        "tcp_add_backlog"
    }
}

#[derive(Default, Clone)]
struct SkbChecksumComplete {}
impl RtraceDrop for SkbChecksumComplete {
    fn get_probe_string(&self) -> &str {
        r#"
[[function]]
name = "__skb_checksum_complete"
params = ["basic", "kretprobe"]
        "#
    }

    fn get_status(&self) -> &str {
        "[Support]"
    }

    fn check_func(&mut self, func: &Func, _vals: &Vec<u64>) -> RtraceDropAction {
        if func.is_kretprobe() {
            let bi = func
                .get_struct(INFO_TYPE::BASIC_INFO)
                .expect("failed to find basic info")
                as *const BASIC_INFO_struct;
            let ret = unsafe { (*bi).ret };
            if ret == 0 {
                return RtraceDropAction::Consume(format!("csum error drop packet"));
            }
        }
        RtraceDropAction::Continue
    }

    fn get_name(&self) -> &str {
        "__skb_checksum_complete"
    }
}
