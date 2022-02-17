use crate::base::{RtraceDrop, RtraceDropAction};
use anyhow::Result;
use rtrace_parser::func::Func;
use rtrace_rs::bindings::*;
use std::boxed::Box;

#[derive(Default, Clone)]
pub struct Iptables {
    points: Vec<Box<dyn RtraceDrop>>,
}

impl RtraceDrop for Iptables {
    fn init(&mut self) -> Result<()> {
        self.points.push(Box::new(IptDoTable::default()));
        Ok(())
    }

    fn get_name(&self) -> &str {
        "iptables"
    }

    fn get_subpoints(&self) -> Option<&Vec<Box<dyn RtraceDrop>>> {
        Some(&self.points)
    }

    fn get_status(&self) -> &str {
        "[Support]"
    }
}

#[derive(Default, Clone)]
struct IptDoTable {
    table: String,
    chain: String,
}

impl RtraceDrop for IptDoTable {
    fn get_probe_string(&self) -> &str {
        r#"
[[function]]
name = "ipt_do_table"
skb = 1
params = ["basic", "kretprobe"]
exprs = ["state.net.ipv4.iptable_filter", "state.net.ipv4.iptable_mangle", "state.net.ipv4.iptable_raw", "state.net.ipv4.arptable_filter", "state.net.ipv4.iptable_security", "state.net.ipv4.nat_table", "table", "state.hook"]
        "#
    }

    fn get_name(&self) -> &str {
        "ipt_do_table"
    }

    fn get_status(&self) -> &str {
        "[Not Support]"
    }

    fn check_func(&mut self, func: &Func, vals: &Vec<u64>) -> RtraceDropAction {
        if func.is_kretprobe() {
            let bi = func
                .get_struct(INFO_TYPE::BASIC_INFO)
                .expect("failed to find basic info")
                as *const BASIC_INFO_struct;
            let ret = unsafe { (*bi).ret };
            if ret == 0 {
                return RtraceDropAction::Consume(format!(
                    "{} of {} drop packet",
                    self.chain, self.table
                ));
            }
        } else {
            self.table = "none".to_owned();
            if vals[6] == vals[0] {
                self.table = "filter".to_owned();
            }
            if vals[6] == vals[0] {
                self.table = "mangle".to_owned();
            }
            if vals[6] == vals[0] {
                self.table = "raw".to_owned();
            }
            if vals[6] == vals[0] {
                self.table = "arp".to_owned();
            }
            if vals[6] == vals[0] {
                self.table = "security".to_owned();
            }
            if vals[6] == vals[0] {
                self.table = "nat".to_owned();
            }

            match vals[7] {
                0 => self.chain = "PREROUTING".to_owned(),
                1 => self.chain = "LOCAL IN".to_owned(),
                2 => self.chain = "FORWARD".to_owned(),
                3 => self.chain = "LOCAL OUT".to_owned(),
                4 => self.chain = "POSTROUTING".to_owned(),
                _ => self.chain = "none".to_owned(),
            }
        }
        RtraceDropAction::Continue
    }
}
