use crate::base::{RtraceDrop, RtraceDropAction};
use anyhow::Result;

#[derive(Default, Clone)]
pub struct L1 {
    points: Vec<Box<dyn RtraceDrop>>,
}

impl RtraceDrop for L1 {
    fn init(&mut self) -> Result<()> {
        for point in &mut self.points {
            point.init()?;
        }
        Ok(())
    }

    fn get_name(&self) -> &str {
        "l1"
    }

    fn get_subpoints(&self) -> Option<&Vec<Box<dyn RtraceDrop>>> {
        Some(&self.points)
    }
}
