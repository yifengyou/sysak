use rtrace_parser::func::Func;
use rtrace_parser::skb::Skb;
use rtrace_rs::bindings::*;
use std::collections::HashMap;
use std::rc::Rc;
use log::*;

struct SynInfo {
    skb: Skb,
    max_ts: u64,
    recv: bool,
}

impl SynInfo {
    pub fn new(recv: bool) -> SynInfo {
        SynInfo {
            skb: Skb::new(recv),
            max_ts: 0,
            recv,
        }
    }

    pub fn push_func(&mut self, func: Func) {
        self.max_ts = std::cmp::max(self.max_ts, func.get_ts());
        self.skb.push_func(Rc::new(func));
    }

    pub fn check_timeout(&mut self, timeout: u64, delay: u64) -> bool {
        if self.max_ts < timeout {
            if self.skb.get_delay() > delay {
                self.skb.show();
            }
            return true;
        }
        false
    }
}

pub struct Syn {
    conn: HashMap<addr_pair, SynInfo>,
    recv: bool,
}

impl Syn {
    pub fn new(protocol: Protocol, recv: bool) -> Syn {
        // match protocol {
        //     Protocol::IPPROTO_TCP_SYN => {}
        //     _ => {
        //         panic!("syn packet only support tcp-syn protocol");
        //     }
        // }
        // if recv {
        //     panic!("syn packet diagnoise now only support send path");
        // }
        Syn {
            conn: HashMap::new(),
            recv,
        }
    }

    pub fn push_func(&mut self, func: Func) {
        debug!("{}: {:?}", func.get_name(),func.get_seq());
        let si = self
            .conn
            .entry(func.get_ap())
            .or_insert(SynInfo::new(self.recv));
        si.push_func(func);
    }

    /// Process timeout data and output
    pub fn check_timeout(&mut self, timeout: u64, delay: u64) {
        self.conn
            .retain(|_, value| value.check_timeout(timeout, delay) == false);
    }
}
