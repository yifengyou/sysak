use rtrace_parser::func::Func;
use rtrace_rs::rtrace::Rtrace;
use rtrace_parser::skb::{funcs_to_skbs, Skb};
use rtrace_parser::net::Net;
use rtrace_rs::bindings::*;
use anyhow::Result;
use std::rc::Rc;
use log::*;

pub struct Mid {
    dis: Vec<u32>,
    skb: Option<Skb>,
    ts: u64,
    recv: bool,
    net : Net,
}

impl Mid {
    pub fn new(protocol: Protocol, recv: bool) -> Mid {
        // match protocol {
        //     Protocol::IPPROTO_TCP | Protocol::IPPROTO_ICMP => {}
        //     _ => {
        //         panic!("only support tcp or icmp(ping) protocol");
        //     }
        // }
        Mid {
            dis: Vec::new(),
            skb: None,
            ts: 0,
            recv,
            net: Net::new(recv),
        }
    }

    pub fn push_func(&mut self, func: Func) {
        debug!("{}: {}, {:?}, {:?}", func.get_name(),func.get_ap().into_string(), func.get_seq(), func.get_rseq());
        self.net.push_func(func);
    }

    pub fn check_timeout(&mut self, timeout: u64, delay: u64) -> bool {
        let vec_funcs = self.net.group(timeout);
        for funcs in vec_funcs {
            let skbs = funcs_to_skbs(funcs, false, self.recv);
            for mut skb in skbs {
                let delay_tmp = skb.get_delay();
                if delay_tmp > delay {
                    skb.show();
                }
            }
        }
        true
    }

    // pub fn check(&mut self, f: Vec<Rc<Func>>, ts: u64) {
    //     let skbs = funcs_to_skbs(f, false, self.recv);
    //     for mut skb in skbs {
    //         let delay = skb.get_delay_ms();
    //         if self.insert_delay(delay as usize) {
    //             self.skb = Some(skb);
    //         }
    //     }

    //     self.show(ts);
    // }

    // fn insert_delay(&mut self, delay: usize) -> bool {
    //     let mut larger = false;
    //     if delay + 1 > self.dis.len() {
    //         self.dis.resize(delay + 1, 0);
    //         larger = true;
    //     }
    //     self.dis[delay as usize] += 1;
    //     larger
    // }

    // fn sum_dis(&self, start: usize, mut end: usize) -> u32 {
    //     let mut res = 0;
    //     end = std::cmp::min(self.dis.len(), end);
    //     for i in start..end {
    //         res += self.dis[i];
    //     }
    //     res
    // }

    // fn show_dis(&self) {
    //     let default_width = 10;
    //     let mut print = Vec::with_capacity(default_width);
    //     let multiple = std::cmp::max(self.dis.len() / default_width, 1);
    //     let mut total_cnt = 0;
    //     println!("DISTRIBUTION:\n");
    //     for i in 0..default_width {
    //         let start = i * multiple;
    //         let end = (i + 1) * multiple;
    //         let res = self.sum_dis(start, end);
    //         total_cnt += res;
    //         print.push(res);
    //     }
    //     if total_cnt == 0 {
    //         return;
    //     }
    //     for i in 0..default_width {
    //         let cnt = print[i] * 50 / total_cnt;
    //         println!(
    //             "{:>5}-{:<5}  {:<50}  {}",
    //             i * multiple,
    //             (i + 1) * multiple,
    //             "*".repeat(cnt as usize),
    //             print[i]
    //         );
    //     }
    // }

    // fn show_skb(&self) {
    //     if let Some(s) = &self.skb {
    //         s.show();
    //     }
    // }

    // pub fn show(&mut self, ts: u64) {
    //     if self.dis.len() == 0 {
    //         return;
    //     }

    //     if ts - self.ts > 1_000_000_000 {
    //         println!("\n");
    //         self.show_dis();
    //         println!("\n");
    //         self.show_skb();
    //         println!("\n\n\n\n\n");
    //         self.ts = ts;
    //     }
    // }
}
