// Copyright 2023-2025, shadow3 (@shadow3aaa)
//
// This file is part of fas-rs.
//
// fas-rs is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// fas-rs is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along
// with fas-rs. If not, see <https://www.gnu.org/licenses/>.

use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use super::Node;
use crate::framework::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Powersave,
    Balance,
    Performance,
    Fast,
}

impl FromStr for Mode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "powersave" => Self::Powersave,
            "balance" => Self::Balance,
            "performance" => Self::Performance,
            "fast" => Self::Fast,
            _ => return Err(Error::ParseNode),
        })
    }
}

impl Display for Mode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mode = match self {
            Self::Powersave => "powersave",
            Self::Balance => "balance",
            Self::Performance => "performance",
            Self::Fast => "fast",
        };

        write!(f, "{mode}")
    }
}

impl Node {
    pub fn get_mode(&mut self) -> Result<Mode> {
        let mode = self.get_node("mode").or(Err(Error::NodeNotFound))?;

        Mode::from_str(mode.trim())
    }
}
