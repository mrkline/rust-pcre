// Copyright 2015 The rust-pcre authors.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use enum_set::{EnumSet};
use libc::{c_char, c_int, c_uchar, c_void};
use libpcre_sys;
pub use libpcre_sys::{pcre, compile_options, exec_options, fullinfo_field, study_options, PCRE_UTF8, PCRE_NO_UTF8_CHECK};
use std::ffi::{CStr};
use std::ptr;
use std::result::{Result};
use std::string::{String};

#[derive(Copy, Clone, Debug)]
pub enum ExecError {
    /// No match was found.
    NoMatch,
    /// The match limit was hit.
    MatchLimit,
    /// A partial match was found.
    /// Try matching on a longer string, if available.
    PartialMatch,
    /// The recursion limit was hit while matching the given input.
    RecursionLimit,
    /// A bad `startoffset` value was provided.
    BadOffset,
    /// The input ended with a partial UTF-8 character
    ShortUtf8,
    /// The given pattern loops recursively.
    RecursionLoop,
    /// The JIT processor ran out of stack space.
    JustInTimeStackLimit,
}

/// Translates raw PCRE error codes to ExecError,
/// and panics on ones we should never encounter
fn translate_error(pcre_err: c_int) -> ExecError {
    use libpcre_sys::*;

    match pcre_err{
        PCRE_ERROR_NOMATCH => ExecError::NoMatch,
        PCRE_ERROR_NULL => panic!("Internal rust-pcre error: null argument"),
        PCRE_ERROR_BADOPTION => panic!("Internal rust-pcre error: bad option"),
        PCRE_ERROR_BADMAGIC => panic!("Internal rust-pcre error: bad magic number (memory issue?)"),
        PCRE_ERROR_UNKNOWN_OPCODE => panic!("Internal rust-pcre error: unknown opcode"),
        // Issued when malloc fails *or* when ovector is bad in pcre_exec().
        // The second case is more likely and a bug in our library, so panic.
        PCRE_ERROR_NOMEMORY => panic!("Internal rust-pcre error: Insufficient ovector"),
        // According to `man pcreapi`, this is only issued from pcre_*_substring
        // functions, and we never call any of them.
        PCRE_ERROR_NOSUBSTRING => panic!("PCRE_ERROR_NOSUBSTRING"),
        PCRE_ERROR_MATCHLIMIT => ExecError::MatchLimit,
        // We don't use utilize callbacks,
        // and pcre_exec() never returns this itself.
        PCRE_ERROR_CALLOUT => panic!("PCRE_ERROR_CALLOUT"),
        // str is assumed to be valid UTF8.
        PCRE_ERROR_BADUTF8 => panic!("libpcre was given invalid UTF-8"),
        // Since we provide PCRE_NO_UTF8_CHECK, we should never get this either.
        PCRE_ERROR_BADUTF8_OFFSET => panic!("libpcre was given an invalid UTF-8 offset"),
        PCRE_ERROR_PARTIAL => ExecError::PartialMatch,
        // According to PCRE docs, this is no longer used.
        PCRE_ERROR_BADPARTIAL => panic!("PCRE_ERROR_BADPARTIAL"),
        // Should we panic if PCRE has an internal problem?
        // For now, assume the answer is yes.
        PCRE_ERROR_INTERNAL => panic!("libpcre internal error"),
        // Issued if ovecsize is negative, which we ensure
        PCRE_ERROR_BADCOUNT => panic!("Internal rust-pcre error: negative ovecsize"),
        PCRE_ERROR_RECURSIONLIMIT => ExecError::RecursionLimit,
        // Issued when a bad combo of PCRE_NEWLINE_* options are given
        PCRE_ERROR_BADNEWLINE => panic!("Internal rust-pcre error: bad option"),
        PCRE_ERROR_SHORTUTF8 => ExecError::ShortUtf8,
        PCRE_ERROR_RECURSELOOP => ExecError::RecursionLoop,
        PCRE_ERROR_JIT_STACKLIMIT => ExecError::JustInTimeStackLimit,
        // Occurs if an 8-bit pattern is passed to a 32-bit library, etc.
        PCRE_ERROR_BADMODE => panic!("Internal rust-pcre error: bad mode"),
        PCRE_ERROR_BADENDIANNESS => panic!("Internal rust-pcre error: bad endianness"),
        // Length is taken from str::len(), so it won't be negative.
        PCRE_ERROR_BADLENGTH => panic!("Internal rust-pcre error: bad length"),
        // Returned from pcre_fullinfo() if we called it without correct params
        PCRE_ERROR_UNSET => panic!("Internal rust-pcre error: pcre info unset"),

        _ => panic!("Unkown error code")
    }
}

pub unsafe fn pcre_compile(pattern: *const c_char, options: &EnumSet<::CompileOption>, tableptr: *const c_uchar) -> Result<*mut pcre, (Option<String>, c_int)> {
    assert!(!pattern.is_null());
    let converted_options = options.iter().fold(0, |converted_options, option| converted_options | (option as compile_options)) | PCRE_UTF8 | PCRE_NO_UTF8_CHECK;
    let mut err: *const c_char = ptr::null();
    let mut erroffset: c_int = 0;
    let code = libpcre_sys::pcre_compile(pattern, converted_options, &mut err, &mut erroffset, tableptr);

    if code.is_null() {
        // "Otherwise, if  compilation  of  a  pattern fails, pcre_compile() returns
        // NULL, and sets the variable pointed to by errptr to point to a textual
        // error message. This is a static string that is part of the library. You
        // must not try to free it."
        // http://pcre.org/pcre.txt
        let err_cstr = CStr::from_ptr(err);
        // http://illegalargumentexception.blogspot.com/2015/05/rust-utf-8-byte-array-to-string.html
        // TODO Investigate memory allocations and check for alternative solutions.
        match String::from_utf8(Vec::from(err_cstr.to_bytes())) {
            Err(_) => Err((None, erroffset)),
            Ok(err_str) => Err((Some(err_str), erroffset))
        }
    } else {
        assert!(!code.is_null());
        assert_eq!(erroffset, 0);

        Ok(code)
    }
}

pub unsafe fn pcre_exec(code: *const pcre, extra: *const ::PcreExtra, subject: *const c_char, length: c_int, startoffset: c_int, options: &EnumSet<::ExecOption>, ovector: *mut c_int, ovecsize: c_int) ->  Result<c_int, ExecError> {
    assert!(!code.is_null());
    assert!(ovecsize >= 0 && ovecsize % 3 == 0);
    let converted_options = options.iter().fold(0, |converted_options, option| converted_options | (option as compile_options)) | PCRE_NO_UTF8_CHECK;
    let rc = libpcre_sys::pcre_exec(code, extra, subject, length, startoffset, converted_options, ovector, ovecsize);
    if rc >= 0 {
        Ok(rc)
    } else {
        Err(translate_error(rc)) // Will panic as needed
    }
}

pub unsafe fn pcre_free(ptr: *mut c_void) {
    libpcre_sys::pcre_free(ptr);
}

pub unsafe fn pcre_free_study(extra: *mut ::PcreExtra) {
    libpcre_sys::pcre_free_study(extra);
}

pub unsafe fn pcre_fullinfo(code: *const pcre, extra: *const ::PcreExtra, what: fullinfo_field, where_: *mut c_void) {
    assert!(!code.is_null());
    let rc = libpcre_sys::pcre_fullinfo(code, extra, what, where_);
    if rc < 0 {
        translate_error(rc); // Should panic
        unreachable!("translate_error didn't panic on an internal error.")
    }
}

pub unsafe fn pcre_refcount(code: *mut ::detail::pcre, adjust: c_int) -> c_int {
    assert!(!code.is_null());
    let curr_refcount = libpcre_sys::pcre_refcount(code, 0);
    if curr_refcount + adjust < 0 {
        panic!("refcount underflow");
    } else if curr_refcount + adjust > 65535 {
        panic!("refcount overflow");
    }
    libpcre_sys::pcre_refcount(code, adjust)
}

pub unsafe fn pcre_study(code: *const ::detail::pcre, options: &EnumSet<::StudyOption>) -> *mut ::PcreExtra {
    assert!(!code.is_null());
    let converted_options = options.iter().fold(0, |converted_options, option| converted_options | (option as study_options));
    let mut err: *const c_char = ptr::null();
    let extra = libpcre_sys::pcre_study(code, converted_options, &mut err);
    // "The third argument for pcre_study() is a pointer for an error message. If
    // studying succeeds (even if no data is returned), the variable it points to is
    // set to NULL. Otherwise it is set to point to a textual error message. This is
    // a static string that is part of the library. You must not try to free it."
    // http://pcre.org/pcre.txt
    if !err.is_null() {
        let err_cstr = CStr::from_ptr(err);
        match String::from_utf8(Vec::from(err_cstr.to_bytes())) {
            Err(_) => panic!("pcre_study() failed"),
            Ok(err_str) => panic!("pcre_study() failed: {}", err_str)
        }
        panic!("pcre_study");
    }
    assert!(err.is_null());

    extra
}

pub fn pcre_version() -> String {
    let version_cstr = unsafe { CStr::from_ptr(libpcre_sys::pcre_version()) };
    String::from_utf8(Vec::from(version_cstr.to_bytes())).unwrap()
}
