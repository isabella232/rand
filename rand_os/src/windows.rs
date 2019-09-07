// Copyright 2018 Developers of the Rand project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Implementation for Windows

extern crate winapi;

pub use self::platform::OsRng;

#[cfg(not(target_vendor = "uwp"))]
mod platform {
    use rand_core::{Error, ErrorKind};
    use super::super::OsRngImpl;

    use std::io;

    use super::winapi::shared::minwindef::ULONG;
    use super::winapi::um::ntsecapi::RtlGenRandom;
    use super::winapi::um::winnt::PVOID;

    #[derive(Clone, Debug)]
    pub struct OsRng;

    impl OsRngImpl for OsRng {
        fn new() -> Result<OsRng, Error> { Ok(OsRng) }

        fn fill_chunk(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            let ret = unsafe {
                RtlGenRandom(dest.as_mut_ptr() as PVOID, dest.len() as ULONG)
            };
            if ret == 0 {
                return Err(Error::with_cause(
                    ErrorKind::Unavailable,
                    "couldn't generate random bytes",
                    io::Error::last_os_error()));
            }
            Ok(())
        }

        fn max_chunk_size(&self) -> usize { <ULONG>::max_value() as usize }

        fn method_str(&self) -> &'static str { "RtlGenRandom" }
    }
}

#[cfg(target_vendor = "uwp")]
mod platform {
    use rand_core::{Error, ErrorKind};
    use std::num::NonZeroU32;
    use std::ptr;
    use super::super::OsRngImpl;
    use super::winapi::shared::bcrypt::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
    use super::winapi::shared::minwindef::ULONG;

    #[derive(Clone, Debug)]
    pub struct OsRng;

    impl OsRngImpl for OsRng {
        fn new() -> Result<OsRng, Error> { Ok(OsRng) }

        fn fill_chunk(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            // Prevent overflow of u32
            for chunk in dest.chunks_mut(u32::max_value() as usize) {
                let ret = unsafe {
                    BCryptGenRandom(
                        ptr::null_mut(),
                        chunk.as_mut_ptr(),
                        chunk.len() as u32,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                    )
                };
                // NTSTATUS codes use two highest bits for severity status
                match ret >> 30 {
                    0b01 => {
                        info!("BCryptGenRandom: information code 0x{:08X}", ret);
                    }
                    0b10 => {
                        warn!("BCryptGenRandom: warning code 0x{:08X}", ret);
                    }
                    0b11 => {
                        error!("BCryptGenRandom: failed with 0x{:08X}", ret);
                        // We zeroize the highest bit, so the error code will reside
                        // inside the range of designated for OS codes.
                        //let code = ret ^ (1 << 31);
                        // SAFETY: the second highest bit is always equal to one,
                        // so it's impossible to get zero. Unfortunately compiler
                        // is not smart enough to figure out it yet.
                        return Err(Error::new(ErrorKind::Unavailable, "couldn't generate random bytes"));
                    }
                    _ => (),
                }
            }
            Ok(())
        }
        
        fn max_chunk_size(&self) -> usize { <ULONG>::max_value() as usize }

        fn method_str(&self) -> &'static str { "BCryptGenRandom" }

    }
}