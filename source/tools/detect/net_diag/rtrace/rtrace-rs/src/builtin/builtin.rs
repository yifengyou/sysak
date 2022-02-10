use anyhow::Result;

use crate::bindings::*;
use crate::rtrace::Function;

/// Builtin paramerters module
///
/// Use this structure to convert the built-in parameter list
/// to a 64-bit mask.
pub struct Builtin {
    mask: u64,
}

impl Builtin {
    ///
    pub fn new(function: &Function) -> Result<Builtin> {
        let mut mask = 0;
        for param in &function.params {
            mask |= 1 << (INFO_TYPE::from_string(param)? as u64);
        }
        // LINEPROBE parameter type is implicit
        if let Some(_) = &function.lines {
            mask |= 1 << (INFO_TYPE::LINEPROBE as u64);
        }

        Ok(Builtin { mask: mask })
    }

    /// Get built-in parameter mask.
    pub fn get_mask(&self) -> u64 {
        self.mask
    }

    /// Whether the built-in parameter list contains the KRETPROBE type.
    pub fn has_kretprobe(&self) -> bool {
        (self.mask & (1 << INFO_TYPE::KRETPROBE as u64)) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_basic() {
        let text = r#"
        name = "test"
        params = ["basic", "kretprobe"]
        "#;
        let function = Function::from_str(text).unwrap();
        let b = Builtin::new(&function).unwrap();

        assert_eq!(b.get_mask(), (1 << 0) | (1 << 3));
        assert_eq!(b.has_kretprobe(), true);
    }
}
