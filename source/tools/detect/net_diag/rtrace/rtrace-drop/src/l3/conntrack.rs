use crate::base::{RtraceDrop, RtraceDropAction};
use anyhow::Result;
use rtrace_parser::func::Func;
use rtrace_rs::bindings::*;
use std::boxed::Box;

#[derive(Default, Clone)]
pub struct Conntrack {
    points: Vec<Box<dyn RtraceDrop>>,
}

impl RtraceDrop for Conntrack {
    fn init(&mut self) -> Result<()> {
        self.points.push(Box::new(Ipv4ConntrackIn::default()));
        self.points.push(Box::new(Ipv4ConntrackLocal::default()));
        self.points.push(Box::new(Ipv4Helper::default()));
        self.points.push(Box::new(Ipv4Confirm::default()));
        Ok(())
    }

    fn get_name(&self) -> &str {
        "conntrack"
    }

    fn get_subpoints(&self) -> Option<&Vec<Box<dyn RtraceDrop>>> {
        Some(&self.points)
    }

    fn get_status(&self) -> &str {
        "[Support]"
    }
}

#[derive(Default, Clone)]
pub struct Ipv4ConntrackIn {}
impl RtraceDrop for Ipv4ConntrackIn {
    fn get_name(&self) -> &str {
        "ipv4_conntrack_in"
    }
}

#[derive(Default, Clone)]
pub struct Ipv4ConntrackLocal {}
impl RtraceDrop for Ipv4ConntrackLocal {
    fn get_name(&self) -> &str {
        "ipv4_conntrack_local"
    }
}

#[derive(Default, Clone)]
pub struct Ipv4Helper {}
impl RtraceDrop for Ipv4Helper {
    fn get_name(&self) -> &str {
        "ipv4_helper"
    }
}

#[derive(Default, Clone)]
pub struct Ipv4Confirm {}
impl RtraceDrop for Ipv4Confirm {
    fn get_name(&self) -> &str {
        "ipv4_confirm"
    }
}
