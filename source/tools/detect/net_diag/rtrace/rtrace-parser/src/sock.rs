use crate::func::Func;
use anyhow::Result;
use log::*;
use rtrace_rs::bindings::*;
use std::collections::BTreeMap;
use std::rc::Rc;

#[derive(Debug)]
pub struct Sock {
    ap: addr_pair,
    seq: Vec<usize>,

    max_send_seq: usize,
    max_recv_seq: usize,
    // usize: Max end seq
    // u64: max ts
    send: BTreeMap<usize, (Vec<Rc<Func>>, usize, u64)>,
    recv: BTreeMap<usize, (Vec<Rc<Func>>, usize, u64)>,
    recv_path: bool,
}

fn bm_insert(
    bm: &mut BTreeMap<usize, (Vec<Rc<Func>>, usize, u64)>,
    seq: (usize, usize),
    func: Rc<Func>,
) {
    let mut item;
    if seq.0 == 0 {
        item = bm.entry(seq.1 - 1).or_insert((Vec::new(), 0, 0));
    } else {
        item = bm.entry(seq.0).or_insert((Vec::new(), 0, 0));
    }
    (*item).1 = std::cmp::max((*item).1, seq.1);
    (*item).2 = std::cmp::max((*item).2, func.get_ts());
    (*item).0.push(func);
}

fn bm_group(bm: &mut BTreeMap<usize, (Vec<Rc<Func>>, usize, u64)>, max_ts: u64) -> Vec<Rc<Func>> {
    let mut funcs = Vec::new();
    let mut keys = Vec::new();
    let mut max_end_seq = 0;

    // println!("bm_group: bmap len is {}, max ts is {}", bm.len(), max_ts);
    for (key, value) in bm.iter() {
        if value.2 > max_ts {
            // println!("{} {}", value.2, max_ts);
            return funcs;
        }

        if max_end_seq == 0 {
            max_end_seq = value.1;
            keys.push(*key);
            continue;
        }

        if *key >= max_end_seq {
            // All func data from min_start_seq to max_end_seq have been found.
            // And the key is not included.
            break;
        } else {
            max_end_seq = std::cmp::max(max_end_seq, value.1);
        }
        // println!(
        //     "seq ({}, {}), max end seq: {}, max_ts: {}",
        //     *key, value.1, max_end_seq, value.2
        // );
        keys.push(*key);
    }

    for key in keys {
        let val = bm.remove(&key);
        if let Some(v) = val {
            funcs.extend(v.0);
        }
    }
    // println!("funcs len is {}", funcs.len());
    funcs
}

impl Sock {
    pub fn new(ap: addr_pair, recv: bool) -> Sock {
        Sock {
            ap: ap,
            max_send_seq: 0,
            max_recv_seq: 0,
            send: BTreeMap::new(),
            recv: BTreeMap::new(),
            seq: Vec::default(),
            recv_path: recv,
        }
    }

    // 1. get avaliable max ts.
    // 2. Call the bm_group function to get the func list,
    //    the func in the list meets the maximum timestamp less than tmp_max_ts,
    //    and the maximum end seq no longer appears in subsequent func.
    // 3. Call push_skb, pending subsequent processing.
    pub fn group_funcs(&mut self, max_ts: u64) -> Vec<Rc<Func>> {
        if self.recv_path {
            bm_group(&mut self.recv, max_ts)
        } else {
            bm_group(&mut self.send, max_ts)
        }
    }

    // 1. insert func into btreemap
    // 2. update max ts
    // 2. try to build one skb
    pub fn push_func(&mut self, func: Func) {
        let rc_func = Rc::new(func);
        if self.recv_path {
            let (rseq, rend_seq) = rc_func.get_rseq();
            bm_insert(&mut self.recv, (rseq, rend_seq), rc_func.clone());
        } else {
            let (seq, end_seq) = rc_func.get_seq();
            bm_insert(&mut self.send, (seq, end_seq), rc_func.clone());
        }
    }

    pub fn get_ap(&self) -> addr_pair {
        self.ap
    }

    pub fn get_rap(&self) -> addr_pair {
        addr_pair {
            saddr: self.ap.daddr,
            sport: u16::from_be(self.ap.dport),
            daddr: self.ap.saddr,
            dport: self.ap.sport.to_be(),
        }
    }
}

#[cfg(test)]
mod sock_tests {
    use super::*;

    #[test]
    fn bm_test() {}
}
