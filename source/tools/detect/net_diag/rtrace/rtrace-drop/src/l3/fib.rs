use crate::base::{RtraceDrop, RtraceDropAction};
use anyhow::Result;
use rtrace_parser::func::Func;
use rtrace_rs::bindings::*;
use std::boxed::Box;

#[derive(Default, Clone)]
pub struct Fib {
    points: Vec<Box<dyn RtraceDrop>>,
}

impl RtraceDrop for Fib {
    fn init(&mut self) -> Result<()> {
        self.points.push(Box::new(FibValidateSource::default()));
        for point in &mut self.points {
            point.init()?;
        }
        Ok(())
    }

    fn get_name(&self) -> &str {
        "fib"
    }

    fn get_subpoints(&self) -> Option<&Vec<Box<dyn RtraceDrop>>> {
        Some(&self.points)
    }

    fn get_status(&self) -> &str {
        "[Support]"
    }
}

#[derive(Default, Clone)]
struct FibValidateSource {}
impl RtraceDrop for FibValidateSource {
    fn get_name(&self) -> &str {
        "fib_validate_source"
    }

    fn get_status(&self) -> &str {
        "[Support: rp_filter]"
    }

    fn check_func(&mut self, func: &Func, vals: &Vec<u64>) -> RtraceDropAction {
        if func.is_kretprobe() {
            let bi = func
                .get_struct(INFO_TYPE::BASIC_INFO)
                .expect("failed to find basic info")
                as *const BASIC_INFO_struct;
            let ret = unsafe { (*bi).ret } as i64;
            if ret < 0 {
                match ret {
                    -18 => return RtraceDropAction::Consume(format!("rp_filter drop packet")),
                    _ => {
                        return RtraceDropAction::Consume(format!(
                            "Unable to parse {}, but the packet is lost here",
                            ret
                        ))
                    }
                }
            }
        }
        RtraceDropAction::Continue
    }
}
