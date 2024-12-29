// Copyright 2023-2024, shadow3 (@shadow3aaa)
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

use std::process::Command;

pub fn setprop<S: AsRef<str>>(k: S, v: S) {
    let key = k.as_ref();
    let value = v.as_ref();
    let _ = Command::new("setprop").args([key, value]).spawn();
}