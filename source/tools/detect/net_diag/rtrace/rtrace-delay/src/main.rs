mod gen;
mod mid;
mod syn;

use crate::gen::gen_config;
use crate::mid::Mid;
use crate::syn::Syn;
use crossbeam_channel;
use log::*;
use rtrace_parser::func::Func;
use rtrace_parser::ksyms::ksyms_load;
use rtrace_parser::perf::{perf_inital_thread2, perf_recv_timeout};
use rtrace_parser::utils;
use rtrace_rs::bindings::*;
use rtrace_rs::rtrace::Rtrace;
use std::path::PathBuf;
use std::time::Duration;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "rtrace_delay", about = "Network delay diagnosis.")]
pub struct Cli {
    #[structopt(long, help = "configuration file path")]
    config: Option<PathBuf>,
    #[structopt(long, help = "generate default configuration file")]
    gen: Option<String>,
    #[structopt(long, default_value = "3000", help = "latency(ms) in processing data")]
    latency: u64,
    #[structopt(
        long,
        default_value = "200",
        help = "show packet routine when delay > DELAY(ms)"
    )]
    delay: u64,
}

fn main() {
    let mut cli = Cli::from_args();
    if let Some(path) = cli.gen {
        gen_config(&path).expect("unable to generate config file");
        return;
    }
    env_logger::init();
    cli.latency = cli.latency * 1_000_000;
    cli.delay = cli.delay * 1_000_000;
    ksyms_load(&"/proc/kallsyms".to_owned());
    let mut rtrace;
    match &cli.config {
        None => {
            println!("Please input config file path");
            return;
        }
        Some(config) => rtrace = Rtrace::from_file(config).expect("rtrace init failed"),
    }
    rtrace.probe_filter().expect("init filter failed");
    rtrace.probe_functions().expect("unable to trace function.");
    let protocol = rtrace.protocol().expect("protocol not specified");
    let recv = rtrace.is_recv();
    let mut syn = Syn::new(protocol, recv);
    let mut mid = Mid::new(protocol, recv);

    let (rx, tx) = crossbeam_channel::unbounded();
    perf_inital_thread2(rtrace.perf_fd(), (rx, tx));

    let mut pre_checktimeout_ts = 0;
    loop {
        let res = perf_recv_timeout(Duration::from_millis(100));
        let cur_ts = utils::get_timestamp();
        match res {
            Ok(data) => {
                let f = Func::new(data.1);
                match protocol {
                    Protocol::IPPROTO_ICMP | Protocol::IPPROTO_TCP => {
                        mid.push_func(f);
                        if cur_ts - pre_checktimeout_ts > 100_000_000 {
                            mid.check_timeout(cur_ts - cli.latency, cli.delay);
                            pre_checktimeout_ts = cur_ts;
                        }
                    }
                    Protocol::IPPROTO_TCP_SYN => {
                        syn.push_func(f);
                        if cur_ts - pre_checktimeout_ts > 100_000_000 {
                            syn.check_timeout(cur_ts - cli.latency, cli.delay);
                            pre_checktimeout_ts = cur_ts;
                        }
                    }
                    _ => {
                        panic!("rtrace_delay only support tcp or syn")
                    }
                }
            }
            _ => {}
        }
    }
}
