use std::collections;

use crate::{InstanceTag, fragment::{self, Fragment}};

pub struct Session {
    instances: collections::HashMap<InstanceTag,Instance>,
}

pub struct Instance {
    assembler: Assembler,
}

pub enum AssemblingError {
    /// Illegal fragment received. Fragment contains bad data and cannot be processed.
    IllegalFragment,
    /// Incomplete result. Waiting for more fragments to arrive.
    IncompleteResult,
    /// Unexpected fragment received. Resetting assembler.
    UnexpectedFragment,
}

const INDEX_FIRST_FRAGMENT: u16 = 1u16;

pub struct Assembler {
    total: u16,
    last: u16,
    content: Vec<u8>,
}

impl Assembler {

    pub fn assemble(&mut self, fragment: Fragment) -> Result<Vec<u8>, AssemblingError> {
        fragment::verify(&fragment).map_err(|_| AssemblingError::IllegalFragment)?;
        if fragment.part == INDEX_FIRST_FRAGMENT {
            self.total = fragment.total;
            self.last = 1;
            self.content.clone_from(&fragment.payload);
        } else if fragment.total == self.total && fragment.part == self.last+1 {
            self.last = fragment.part;
            self.content.extend_from_slice(&fragment.payload);
        } else {
            self.total = 0;
            self.last = 0;
            self.content.clear();
            return Err(AssemblingError::UnexpectedFragment);
        }
        if self.last == self.total {
            return Ok(Vec::from(self.content.as_slice()))
        }
        return Err(AssemblingError::IncompleteResult)
    }
}
