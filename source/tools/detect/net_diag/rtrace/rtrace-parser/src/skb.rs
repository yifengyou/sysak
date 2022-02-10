use crate::func::Func;
use crate::sock::Sock;
use crate::utils::*;
use rtrace_rs::bindings::*;
use std::collections::HashMap;
use std::rc::Rc;

#[derive(Debug, Default)]
pub struct Skb {
    min_seq: usize,
    end_seq: usize,
    delay: u64,
    funcs: Vec<Rc<Func>>,
    max_ts: u64,
    recv: bool,
}

impl Skb {
    pub fn new(recv: bool) -> Skb {
        Skb {
            min_seq: usize::MAX,
            end_seq: 0,
            delay: u64::MAX,
            funcs: Vec::new(),
            max_ts: 0,
            recv,
        }
    }

    pub fn funcs_len(&self) -> usize {
        self.funcs.len()
    }

    pub fn push_func(&mut self, func: Rc<Func>) {
        let tmp;
        if self.recv {
            tmp = func.get_rseq();
        } else {
            tmp = func.get_seq();
        }
        if tmp.0 != 0 {
            self.min_seq = std::cmp::min(self.min_seq, tmp.0);
        }
        if tmp.0 == 0 && self.min_seq == usize::MAX {
            self.min_seq = 0;
        }
        self.max_ts = std::cmp::max(self.max_ts, func.get_ts());
        self.funcs.push(func);
    }

    pub fn from_funcs(funcs: Vec<Rc<Func>>, recv: bool) -> Skb {
        let mut skb = Skb::new(recv);
        for func in funcs {
            skb.push_func(func);
        }
        skb
    }

    pub fn get_funcs_by_name(&self, name: &String) -> Vec<Rc<Func>> {
        let mut funcs = Vec::new();
        for func in &self.funcs {
            if name.eq(func.get_name()) {
                funcs.push(func.clone());
            }
        }
        funcs
    }

    pub fn get_delay(&mut self) -> u64 {
        if self.delay == u64::MAX {
            self.funcs.sort_by(|a, b| a.get_ts().cmp(&b.get_ts()));
            self.delay = self.funcs.last().unwrap().get_ts() - self.funcs.first().unwrap().get_ts();
        }
        self.delay
    }

    pub fn get_delay_ms(&mut self) -> u64 {
        let delay = self.get_delay();
        delay / 1000_000
    }

    pub fn get_max_ts(&self) -> u64 {
        self.max_ts
    }

    pub fn show(&self) {
        if self.funcs.len() == 0 {
            return;
        }
        println!("FUNCTION DELAY: {}\n", self.funcs[0].get_ap().into_string());
        let mut row = (self.funcs.len() as f64).sqrt() as usize;
        if row * row < self.funcs.len() {
            row += 1;
        }
        let index_table = get_index_table(row);

        for i in 0..row {
            // first line
            for j in 0..row {
                let index = index_table[i][j];
                if index >= self.funcs.len() {
                    continue;
                }

                let mut seq;
                if self.recv {
                    seq = self.funcs[index].get_rseq();
                    if seq.0 == 0 {
                        seq.0 = self.min_seq;
                    }
                } else {
                    seq = self.funcs[index].get_seq();
                }
                let name = self.funcs[index].get_kretname();
                // let ts = self.funcs[index].get_ts();

                if i != 0 && i != row - 1 && j != 0 {
                    print!("{:^10}", " ");
                }

                if i == 0 && j != 0 {
                    if j % 2 == 0 {
                        let ts = self.funcs[index].get_ts() - self.funcs[index - 1].get_ts();
                        let tmp_str = format!("→{}us→", ts / 1000);
                        print!("{:^10}", tmp_str)
                    } else {
                        print!("{:^10}", " ");
                    }
                }

                if i == row - 1 && j != 0 {
                    if j % 2 == 1 {
                        let ts = self.funcs[index].get_ts() - self.funcs[index - 1].get_ts();
                        let tmp_str = format!("→{}us→", ts / 1000);
                        print!("{:^10}", tmp_str);
                    } else {
                        print!("{:^10}", " ");
                    }
                }
                let tmp_str = format!(
                    "({},{}){}",
                    seq.0 - self.min_seq,
                    seq.1 - self.min_seq,
                    name
                );
                print!("{:^30}", tmp_str);
            }
            println!("");
            if i != row - 1 {
                // second line
                for j in 0..row {
                    let index = index_table[i][j];
                    if index >= self.funcs.len() {
                        continue;
                    }
                    if j % 2 == 0 {
                        print!("{:^30}", "↓");
                    } else {
                        print!("{:^30}", "↑");
                    }
                    print!("{:^10}", " ");
                }
                println!("");
                // thrid line
                for j in 0..row {
                    let index = index_table[i][j];
                    let nxt_index = index_table[i + 1][j];
                    if index >= self.funcs.len() || nxt_index >= self.funcs.len() {
                        continue;
                    }
                    let ts = self.funcs[index].get_ts();
                    let nxt_ts = self.funcs[nxt_index].get_ts();
                    let val;
                    if ts < nxt_ts {
                        val = nxt_ts - ts;
                    } else {
                        val = ts - nxt_ts;
                    }
                    let tmp_str = format!("{}us", val / 1000);
                    print!("{:^30}", tmp_str);
                    print!("{:^10}", " ");
                }
                println!("");
                // fourth line
                for j in 0..row {
                    let index = index_table[i][j];
                    if index >= self.funcs.len() {
                        continue;
                    }
                    if j % 2 == 0 {
                        print!("{:^30}", "↓");
                    } else {
                        print!("{:^30}", "↑");
                    }
                    print!("{:^10}", " ");
                }
                println!("");
            }
        }
        println!("\n");
    }

    pub fn show_brief(&self) {}
}

pub fn funcs_to_skbs(funcs: Vec<Rc<Func>>, raw: bool, recv: bool) -> Vec<Skb> {
    let mut skbs = Vec::new();
    if raw {
        skbs.push(Skb::from_funcs(funcs, recv));
    } else {
        let mut seqs = Vec::new();
        if recv {
            for func in &funcs {
                let (sseq, eseq) = func.get_rseq();
                if sseq != 0 {
                    seqs.push(sseq);
                }
                seqs.push(eseq);
            }
        } else {
            for func in &funcs {
                let (sseq, eseq) = func.get_seq();
                seqs.push(sseq);
                seqs.push(eseq);
            }
        }
        seqs.sort_unstable();
        seqs.dedup();

        if seqs.len() == 1 {
            seqs.push(seqs[0]);
        }

        for i in 1..seqs.len() {
            let mut skb = Skb::new(recv);
            if recv {
                for func in &funcs {
                    let (sseq, eseq) = func.get_rseq();
                    if seqs[i - 1] >= sseq && seqs[i] <= eseq {
                        skb.push_func(func.clone());
                    }
                }
            } else {
                for func in &funcs {
                    let (sseq, eseq) = func.get_seq();
                    if seqs[i - 1] >= sseq && seqs[i] <= eseq {
                        skb.push_func(func.clone());
                    }
                }
            }
            if skb.funcs_len() != 0 {
                skbs.push(skb);
            }
        }
    }

    skbs
}

// if self.skb_raw {
//     skbs.push(Skb::from_vec(funcs, true));
// } else {
//     for func in funcs {
//         let (sseq, eseq) = func.get_seq();
//         seqs.push(sseq);
//         seqs.push(eseq);
//     }
//     seqs.sort_unstable();
//     seqs.dedup();
// }
