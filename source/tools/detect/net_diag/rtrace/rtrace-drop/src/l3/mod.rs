mod conntrack;
mod fib;
mod iptables;

use crate::base::RtraceDrop;
use crate::l3::conntrack::Conntrack;
use crate::l3::fib::Fib;
use crate::l3::iptables::Iptables;
use anyhow::Result;

#[derive(Default, Clone)]
pub struct L3 {
    points: Vec<Box<dyn RtraceDrop>>,
}

impl RtraceDrop for L3 {
    fn init(&mut self) -> Result<()> {
        self.points.push(Box::new(Iptables::default()));
        self.points.push(Box::new(Conntrack::default()));
        self.points.push(Box::new(Fib::default()));
        for point in &mut self.points {
            point.init()?;
        }
        Ok(())
    }

    fn get_name(&self) -> &str {
        "l3"
    }

    fn get_subpoints(&self) -> Option<&Vec<Box<dyn RtraceDrop>>> {
        Some(&self.points)
    }
}
