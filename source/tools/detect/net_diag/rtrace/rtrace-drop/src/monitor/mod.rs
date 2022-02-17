mod netlink;
mod proc;

use crate::base::{RtraceDrop, RtraceDropAction};
use crate::monitor::netlink::Netlink;
use crate::monitor::proc::Proc;
use anyhow::Result;

#[derive(Default, Clone)]
pub struct Mointor {
    points: Vec<Box<dyn RtraceDrop>>,
}

impl RtraceDrop for Mointor {
    fn init(&mut self) -> Result<()> {
        self.points.push(Box::new(Netlink::default()));
        self.points.push(Box::new(Proc::default()));
        for point in &mut self.points {
            point.init()?;
        }
        Ok(())
    }

    fn get_name(&self) -> &str {
        "mointor"
    }

    fn get_subpoints(&self) -> Option<&Vec<Box<dyn RtraceDrop>>> {
        Some(&self.points)
    }
}
