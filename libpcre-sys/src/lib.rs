// Copyright 2015 The rust-pcre authors.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate libc;

use libc::{c_char, c_int, c_uchar, c_ulong, c_void};
use std::option::{Option};
use std::ptr;

#[allow(non_camel_case_types)]
pub type compile_options = c_int;
#[allow(non_camel_case_types)]
pub type exec_options = c_int;
#[allow(non_camel_case_types)]
pub type fullinfo_field = c_int;
#[allow(non_camel_case_types)]
pub type study_options = c_int;

pub const PCRE_UTF8: compile_options = 0x00000800;

// PCRE_NO_UTF8_CHECK is both a compile and exec option
pub const PCRE_NO_UTF8_CHECK: c_int = 0x00002000;

pub const PCRE_ERROR_NOMATCH: c_int = -1;
pub const PCRE_ERROR_NULL: c_int = -2;
pub const PCRE_ERROR_BADOPTION: c_int = -3;
pub const PCRE_ERROR_BADMAGIC: c_int = -4;
pub const PCRE_ERROR_UNKNOWN_OPCODE: c_int = -5;
pub const PCRE_ERROR_NOMEMORY: c_int = -6;
pub const PCRE_ERROR_NOSUBSTRING: c_int = -7;
pub const PCRE_ERROR_MATCHLIMIT: c_int = -8;
pub const PCRE_ERROR_CALLOUT: c_int = -9;  // Never used by PCRE itself
pub const PCRE_ERROR_BADUTF8: c_int = -10;
pub const PCRE_ERROR_BADUTF8_OFFSET: c_int = -11;  // Same for 8/16
pub const PCRE_ERROR_PARTIAL: c_int = -12;
pub const PCRE_ERROR_BADPARTIAL: c_int = -13; // No longer used.
pub const PCRE_ERROR_INTERNAL: c_int = -14;
pub const PCRE_ERROR_BADCOUNT: c_int = -15;
pub const PCRE_ERROR_DFA_UITEM: c_int = -16;
pub const PCRE_ERROR_DFA_UCOND: c_int = -17;
pub const PCRE_ERROR_DFA_UMLIMIT: c_int = -18;
pub const PCRE_ERROR_DFA_WSSIZE: c_int = -19;
pub const PCRE_ERROR_DFA_RECURSE: c_int = -20;
pub const PCRE_ERROR_RECURSIONLIMIT: c_int = -21;
pub const PCRE_ERROR_BADNEWLINE: c_int = -23;
pub const PCRE_ERROR_BADOFFSET: c_int = -24;
pub const PCRE_ERROR_SHORTUTF8: c_int = -25;
pub const PCRE_ERROR_RECURSELOOP: c_int = -26;
pub const PCRE_ERROR_JIT_STACKLIMIT: c_int = -27;
pub const PCRE_ERROR_BADMODE: c_int = -28;
pub const PCRE_ERROR_BADENDIANNESS: c_int = -29;
pub const PCRE_ERROR_DFA_BADRESTART: c_int = -30;
pub const PCRE_ERROR_JIT_BADOPTION: c_int = -31;
pub const PCRE_ERROR_BADLENGTH: c_int = -32;
pub const PCRE_ERROR_UNSET: c_int = -33;

pub const PCRE_INFO_CAPTURECOUNT: fullinfo_field = 2;
pub const PCRE_INFO_NAMEENTRYSIZE: fullinfo_field = 7;
pub const PCRE_INFO_NAMECOUNT: fullinfo_field = 8;
pub const PCRE_INFO_NAMETABLE: fullinfo_field = 9;

//const PCRE_EXTRA_STUDY_DATA: c_ulong = 0x0001;
const PCRE_EXTRA_MATCH_LIMIT: c_ulong = 0x0002;
//const PCRE_EXTRA_CALLOUT_DATA: c_ulong = 0x0004;
//const PCRE_EXTRA_TABLES: c_ulong = 0x0008;
const PCRE_EXTRA_MATCH_LIMIT_RECURSION: c_ulong = 0x0010;
const PCRE_EXTRA_MARK: c_ulong = 0x0020;
//const PCRE_EXTRA_EXECUTABLE_JIT: c_ulong = 0x0040;

#[allow(non_camel_case_types)]
pub enum pcre {}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct pcre_extra {
    flags: c_ulong,
    study_data: *mut c_void,
    match_limit_: c_ulong,
    callout_data: *mut c_void,
    tables: *const c_uchar,
    match_limit_recursion_: c_ulong,
    mark: *mut *mut c_uchar,
    executable_jit: *mut c_void
}

impl pcre_extra {
    /// Returns the match limit, if previously set by [set_match_limit()](#method.set_match_limit).
    ///
    /// The default value for this limit is set when PCRE is built. The default default is 10 million.
    pub fn match_limit(&self) -> Option<usize> {
        if (self.flags & PCRE_EXTRA_MATCH_LIMIT) == 0 {
            None
        } else {
            Some(self.match_limit_ as usize)
        }
    }

    /// Sets the match limit to `limit` instead of using PCRE's default.
    pub fn set_match_limit(&mut self, limit: u32) {
        self.flags |= PCRE_EXTRA_MATCH_LIMIT;
        self.match_limit_ = limit as c_ulong;
    }

    /// Returns the recursion depth limit, if previously set by [set_match_limit_recursion()](#method.set_match_limit_recursion).
    ///
    /// The default value for this limit is set when PCRE is built.
    pub fn match_limit_recursion(&self) -> Option<usize> {
        if (self.flags & PCRE_EXTRA_MATCH_LIMIT_RECURSION) == 0 {
            None
        } else {
            Some(self.match_limit_recursion_ as usize)
        }
    }

    /// Sets the recursion depth limit to `limit` instead of using PCRE's default.
    pub fn set_match_limit_recursion(&mut self, limit: u32) {
        self.flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
        self.match_limit_ = limit as c_ulong;
    }

    /// Sets the mark field.
    pub unsafe fn set_mark(&mut self, mark: &mut *mut c_uchar) {
        self.flags |= PCRE_EXTRA_MARK;
        self.mark = mark as *mut *mut c_uchar;
    }

    /// Unsets the mark field. PCRE will not save mark names when matching the compiled regular expression.
    pub fn unset_mark(&mut self) {
        self.flags &= !PCRE_EXTRA_MARK;
        self.mark = ptr::null_mut();
    }
}

#[link(name = "pcre")]
extern {
    pub static pcre_free: extern "C" fn(ptr: *mut c_void);

    pub fn pcre_compile(pattern: *const c_char, options: compile_options, errptr: *mut *const c_char, erroffset: *mut c_int, tableptr: *const c_uchar) -> *mut pcre;
    pub fn pcre_exec(code: *const pcre, extra: *const pcre_extra, subject: *const c_char, length: c_int, startoffset: c_int, options: exec_options, ovector: *mut c_int, ovecsize: c_int) -> c_int;
    pub fn pcre_free_study(extra: *mut pcre_extra);
    pub fn pcre_fullinfo(code: *const pcre, extra: *const pcre_extra, what: fullinfo_field, where_: *mut c_void) -> c_int;
    // Note: libpcre's pcre_refcount() function is not thread-safe.
    pub fn pcre_refcount(code: *mut pcre, adjust: c_int) -> c_int;
    pub fn pcre_study(code: *const pcre, options: study_options, errptr: *mut *const c_char) -> *mut pcre_extra;
    pub fn pcre_version() -> *const c_char;
}
