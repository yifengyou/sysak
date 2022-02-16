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
}
