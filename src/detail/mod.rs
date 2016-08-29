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
pub use libpcre_sys::{pcre, compile_options, exec_options, fullinfo_field, study_options, PCRE_UTF8, PCRE_NO_UTF8_CHECK, PCRE_ERROR_NOMATCH, PCRE_ERROR_NULL, PCRE_ERROR_PARTIAL};
use std::ffi::{CStr};
use std::ptr;
use std::result::{Result};
use std::string::{String};

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

pub unsafe fn pcre_exec(code: *const pcre, extra: *const ::PcreExtra, subject: *const c_char, length: c_int, startoffset: c_int, options: &EnumSet<::ExecOption>, ovector: *mut c_int, ovecsize: c_int) -> c_int {
    assert!(!code.is_null());
    assert!(ovecsize >= 0 && ovecsize % 3 == 0);
    let converted_options = options.iter().fold(0, |converted_options, option| converted_options | (option as compile_options)) | PCRE_NO_UTF8_CHECK;
    let rc = libpcre_sys::pcre_exec(code, extra, subject, length, startoffset, converted_options, ovector, ovecsize);
    if rc == PCRE_ERROR_NOMATCH {
        return -1;
    } else if rc < 0 && rc != PCRE_ERROR_NULL && rc != PCRE_ERROR_PARTIAL {
        panic!("pcre_exec");
    }

    rc
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
    if rc < 0 && rc != PCRE_ERROR_NULL {
        panic!("pcre_fullinfo");
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
