mod base;
mod l1;
mod l2;
mod l3;
mod l4;
mod monitor;

use crate::base::{RtraceDrop, RtraceDropAction};
use crate::l1::L1;
use crate::l2::L2;
use crate::l3::L3;
use crate::l4::L4;
use crate::monitor::Mointor;
use anyhow::anyhow;
use anyhow::Result;
use log::*;
use rtrace_parser::func::Func;
use rtrace_parser::ksyms::ksyms_load;
use rtrace_parser::perf::{perf_inital_thread2, perf_recv_timeout};
use rtrace_parser::utils;
use rtrace_rs::rtrace::{Config, FunctionContainer, Rtrace};
use std::boxed::Box;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use structopt::StructOpt;
use uname::uname;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "rtrace_drop",
    about = "Network packet drop traceability diagnosis"
)]
pub struct Cli {
    #[structopt(long, help = "configuration file path")]
    config: Option<PathBuf>,
    #[structopt(long, help = "generate default configuration file")]
    gen: Option<String>,
    #[structopt(long, short, help = "Included drop points")]
    include: Option<Vec<String>>,
    #[structopt(long, short, help = "Exclude packet loss points")]
    exclude: Option<Vec<String>>,
    #[structopt(long, short, help = "show all packet loss points")]
    list: Option<Vec<String>>,
    #[structopt(
        long,
        short,
        default_value = "1",
        help = "monitor program running cycle, defaule 1 second"
    )]
    period: u64,
}

/// main entry
#[derive(Default, Clone)]
struct AllDrop {
    points: Vec<Box<dyn RtraceDrop>>,
}

impl RtraceDrop for AllDrop {
    fn init(&mut self) -> Result<()> {
        // l1 to l4
        self.points.push(Box::new(L1::default()));
        self.points.push(Box::new(L2::default()));
        self.points.push(Box::new(L3::default()));
        self.points.push(Box::new(L4::default()));
        self.points.push(Box::new(Mointor::default()));
        for point in &mut self.points {
            point.init()?;
        }
        Ok(())
    }

    fn get_subpoints(&self) -> Option<&Vec<Box<dyn RtraceDrop>>> {
        Some(&self.points)
    }

    fn get_name(&self) -> &str {
        "all"
    }
}

fn main() {
    env_logger::init();
    let mut cli = Cli::from_args();
    let include_hs = build_hs(&cli.include, "all");
    let exclude_hs = build_hs(&cli.exclude, "none");
    let list_hs = build_hs(&cli.list, "all");
    let mut ad: Box<dyn RtraceDrop> = Box::new(AllDrop::default());
    ad.init().expect("failed to init drop instance");

    if let Some(path) = cli.gen {
        gen_config(&path).expect("unable to generate config file");
        return;
    }

    if list_hs.len() != 0 {
        list_points(&ad, &list_hs, 0, false);
        return;
    }

    let mut rtrace;

    match &cli.config {
        Some(config) => rtrace = Rtrace::from_file(config).expect("failed to create Rtrace object"),
        None => {
            println!("please specify config file");
            return;
        }
    }
    ksyms_load(&"/proc/kallsyms".to_owned());
    rtrace.probe_filter().expect("init filter failed");

    let mut enabled_points =
        get_enabled_points(&ad, &include_hs, &exclude_hs).expect("failed to solve points");
    let function_mapping =
        probe_funcitons(&mut rtrace, &enabled_points).expect("Failed to insert probe functions");

    let (rx, tx) = crossbeam_channel::unbounded();
    perf_inital_thread2(rtrace.perf_fd(), (rx, tx));

    let mut pre_checktimeout_ts = 0;
    cli.period = cli.period * 1_000_000_000;
    loop {
        let res = perf_recv_timeout(Duration::from_millis(100));
        match res {
            Ok(data) => {
                let f = Func::new(data.1);
                match function_mapping.get(&f.get_name_no_offset()) {
                    None => {}
                    Some(names) => {
                        let vals = get_exprs_vals(&rtrace, &f)
                            .expect("failed to parse expression values.");
                        for name in names {
                            if let Some(point) = enabled_points.get_mut(name) {
                                match point.0.check_func(&f, &vals) {
                                    RtraceDropAction::Continue => {}
                                    RtraceDropAction::Consume(x) => {
                                        println!("{}", x);
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        let cur_ts = utils::get_timestamp();
        if cur_ts - pre_checktimeout_ts > cli.period {
            for (_, v) in enabled_points.iter_mut() {
                if v.0.is_periodic() {
                    match v.0.run_periodically() {
                        RtraceDropAction::Continue => {}
                        RtraceDropAction::Consume(x) => {
                            println!("{}", x);
                            return;
                        }
                    }
                }
            }
            pre_checktimeout_ts = cur_ts;
        }
    }
}

fn get_exprs_vals(rtrace: &Rtrace, f: &Func) -> Result<Vec<u64>> {
    // todo: fix confict
    let mut vals = Vec::new();
    let name = f.get_name_no_offset();
    if let Some(probe) = rtrace.get_probe(&name) {
        let mut off = 0;
        let mut val;
        for sz in probe.get_expr_sz() {
            let ptr = f.get_extra(off as usize);
            match sz {
                1 => val = unsafe { *ptr } as u64,
                2 => val = unsafe { *(ptr as *const u16) } as u64,
                4 => val = unsafe { *(ptr as *const u32) } as u64,
                8 => val = unsafe { *(ptr as *const u64) },
                _ => return Err(anyhow!("size: {} not support", sz)),
            }
            vals.push(val);
            off += sz;
        }
    } else {
        return Err(anyhow!("entry {} not found in probes of rtrace", name));
    }
    Ok(vals)
}

fn gen_config(path: &str) -> Result<()> {
    let mut p = PathBuf::from(path);
    std::fs::create_dir_all(&p)?;
    p.push("drop.toml");
    let text = r#"
[basic]
debug = false
duration = 0
protocol = "tcp"
recv = true
[[filter]]
pid = 0
dst = "0.0.0.0:0"
src = "0.0.0.0:0"
    "#;
    let mut config = Config::from_str(text)?;
    config.basic.btf_path = Some(get_btf_path());
    let string = Config::to_string(&config)?;
    let mut output = std::fs::File::create(p)?;
    write!(output, "{}", string)?;
    Ok(())
}

fn probe_funcitons(
    rtrace: &mut Rtrace,
    enabled_points: &HashMap<String, (Box<dyn RtraceDrop>, FunctionContainer)>,
) -> Result<HashMap<String, Vec<String>>> {
    let mut function_mapping = HashMap::new();
    let mut function_hm = HashMap::new();
    for (_, point) in enabled_points {
        for function in &point.1.function {
            function_hm
                .entry(function.name.clone())
                .or_insert(function.clone());

            let tmp = function_mapping
                .entry(function.name.clone())
                .or_insert(Vec::new());
            tmp.push(point.0.get_name().to_string());
        }
    }

    let mut functions = Vec::new();
    for (_, mut v) in function_hm {
        debug!("probe packet drop point: {}", v.name);
        v.enable = Some(true);
        functions.push(v);
    }

    rtrace.probe_functions_from_functions(&functions)?;
    Ok(function_mapping)
}

fn get_btf_path() -> String {
    let mut default = String::from("/boot/vmlinux-");
    let info = uname().expect("uname failed");
    default.push_str(&info.release[..]);
    default
}

// get enabled points according to include and exclude.
fn get_enabled_points(
    rd: &Box<dyn RtraceDrop>,
    include_hs: &HashSet<String>,
    exclude_hs: &HashSet<String>,
) -> Result<HashMap<String, (Box<dyn RtraceDrop>, FunctionContainer)>> {
    let mut enabled_points = HashMap::new();
    let mut disabled_points = HashMap::new();
    let mut returned_points = HashMap::new();
    if include_hs.len() == 0 {
        build_enabled_points(&mut enabled_points, rd, &include_hs, true);
    } else {
        build_enabled_points(&mut enabled_points, rd, &include_hs, false);
    }
    if exclude_hs.len() != 0 {
        build_disabled_points(&mut disabled_points, rd, &exclude_hs, false);
    }

    // exclude has the higher priority than include.
    for (name, _) in &disabled_points {
        match enabled_points.remove(name) {
            None => warn!("Set exclude flag {} is meaningless", name),
            _ => {}
        }
    }
    // clone all enabled points.
    for (name, point) in enabled_points {
        let probe_str = point.get_probe_string();
        let fc;
        if probe_str.len() == 0 {
            fc = FunctionContainer::default();
        } else {
            fc = FunctionContainer::from_str(&point.get_probe_string())?;
        }
        returned_points.insert(name, (point.clone(), fc));
    }
    Ok(returned_points)
}

// generate disabled points according to include.
fn build_enabled_points<'a>(
    enabled_points: &mut HashMap<String, &'a Box<dyn RtraceDrop>>,
    rd: &'a Box<dyn RtraceDrop>,
    hs: &HashSet<String>,
    mut parent_enable: bool,
) {
    let name = rd.get_name();
    if parent_enable == false && hs.contains(name) {
        parent_enable = true;
    }
    if parent_enable {
        enabled_points.entry(name.clone().to_owned()).or_insert(rd);
    }

    if let Some(points) = rd.get_subpoints() {
        for point in points {
            build_enabled_points(enabled_points, point, hs, parent_enable);
        }
    }
}

// generate disabled points according to exclude.
fn build_disabled_points<'a>(
    disabled_points: &mut HashMap<String, &'a Box<dyn RtraceDrop>>,
    rd: &'a Box<dyn RtraceDrop>,
    hs: &HashSet<String>,
    mut parent_disable: bool,
) {
    let name = rd.get_name();
    if parent_disable == false && hs.contains(name) {
        parent_disable = true;
    }
    if parent_disable {
        disabled_points.entry(name.clone().to_owned()).or_insert(rd);
    }

    if let Some(points) = rd.get_subpoints() {
        for point in points {
            build_disabled_points(disabled_points, point, hs, parent_disable);
        }
    }
}

// Display currently supported and unsupported packet drop points.
fn list_points(
    rd: &Box<dyn RtraceDrop>,
    hs: &HashSet<String>,
    indent: usize,
    mut parent_enable: bool,
) {
    let name = rd.get_name();
    if parent_enable == false && hs.contains(name) {
        parent_enable = true;
    }
    if parent_enable {
        print!("{:indent$}{:<30}", "", name, indent = indent * 4);
        match rd.get_subpoints() {
            // Implement RtraceDrop as a module.
            Some(_) => println!(),
            // Implement RtraceDrop as a specific packet drop point.
            None => println!("\t\t{}", rd.get_status()),
        }
    }
    if let Some(points) = rd.get_subpoints() {
        for point in points {
            list_points(point, hs, indent + 1, parent_enable);
        }
    }
}

// Translate `Vec<String>` to `HashSet`. If vec is None,
// we will insert a default data.
fn build_hs(vec: &Option<Vec<String>>, default: &str) -> HashSet<String> {
    let mut hs = HashSet::new();
    if let Some(items) = vec {
        for item in items {
            hs.insert(item.clone());
        }

        if hs.len() == 0 {
            hs.insert(default.to_owned());
        }
    }
    hs
}
