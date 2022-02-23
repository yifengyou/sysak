mod tcp;
mod udp;

use crate::base::RtraceDrop;
use crate::l4::tcp::Tcp;
use crate::l4::udp::Udp;
use anyhow::Result;

#[derive(Default, Clone)]
pub struct L4 {
    points: Vec<Box<dyn RtraceDrop>>,
}

impl RtraceDrop for L4 {
    fn init(&mut self) -> Result<()> {
        self.points.push(Box::new(Tcp::default()));
        self.points.push(Box::new(Udp::default()));
        for point in &mut self.points {
            point.init()?;
        }
        Ok(())
    }

    fn get_subpoints(&self) -> Option<&Vec<Box<dyn RtraceDrop>>> {
        Some(&self.points)
    }

    fn get_name(&self) -> &str {
        "l4"
    }
}
