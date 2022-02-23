use crate::base::{RtraceDrop, RtraceDropAction};
use anyhow::Result;

#[derive(Default, Clone)]
pub struct Proc {
    points: Vec<Box<dyn RtraceDrop>>,
}

impl RtraceDrop for Proc {
    fn init(&mut self) -> Result<()> {
        self.points.push(Box::new(TcpTwRecycle::default()));
        for point in &mut self.points {
            point.init()?;
        }
        Ok(())
    }

    fn get_name(&self) -> &str {
        "proc"
    }
    fn get_subpoints(&self) -> Option<&Vec<Box<dyn RtraceDrop>>> {
        Some(&self.points)
    }
}

#[derive(Default, Clone)]
struct TcpTwRecycle {
    run: bool,
}

impl RtraceDrop for TcpTwRecycle {
    fn get_name(&self) -> &str {
        "tcp_tw_recycle"
    }

    fn is_periodic(&self) -> bool {
        true
    }

    fn run_periodically(&mut self) -> RtraceDropAction {
        if self.run {
            return RtraceDropAction::Continue;
        }
        self.run = true;
        let path = std::path::Path::new("/proc/sys/net/ipv4/tcp_tw_recycle");
        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(mut x) => {
                    x.truncate(x.len() - 1);
                    let recycle = x.parse::<i32>().expect("failed to parse string to number");
                    if recycle != 0 {
                        return RtraceDropAction::Consume(format!(
                            "tcp_tw_recycle not closed: {}",
                            recycle
                        ));
                    }
                }
                Err(y) => {
                    println!("failed to check tcp_tw_recycle: {:?}", y);
                }
            }
        }
        RtraceDropAction::Continue
    }

    fn get_status(&self) -> &str {
        "[Support]"
    }
}
