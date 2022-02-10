use crate::func::Func;
use crate::sock::Sock;
use anyhow::Result;
use log::*;
use rtrace_rs::bindings::*;
use std::collections::HashMap;
use std::rc::Rc;

pub struct Net {
    sockmap: HashMap<addr_pair, Sock>,
    funcs: Vec<Func>,
    recv: bool,
}

impl Net {
    pub fn new(recv: bool) -> Net {
        let mut n = Net {
            sockmap: HashMap::new(),
            funcs: Vec::new(),
            recv,
        };
        n
    }

    // 1. Get the network quadruple according to Func
    // 2. Get sock
    // 3. Send func to the sock
    pub fn push_func(&mut self, func: Func) {
        // if self.recv {
        //     println!("name: {}, seq:{:?}", func.get_name(), func.get_rseq());
        // } else {
        //     println!("name: {}, seq:{:?}", func.get_name(), func.get_seq());
        // }
        // unsafe {println!("{:?}", (*(func.get_struct(INFO_TYPE::BASIC_INFO).unwrap() as *const BASIC_INFO_struct)).into_string());}
        let ap = func.get_ap();
        let sk = self.sockmap.entry(ap).or_insert(Sock::new(ap, self.recv));
        if log_enabled!(Level::Info) {
            func.show_brief();
        }
        sk.push_func(func);
    }

    pub fn group(&mut self, max_ts: u64) -> Vec<Vec<Rc<Func>>> {
        let mut res = Vec::new();
        for (_, sk) in &mut self.sockmap {
            let tmp = sk.group_funcs(max_ts);
            if tmp.len() != 0 {
                res.push(tmp);
            }
        }
        res
    }
}
