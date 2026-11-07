// Copyright (c) 2026 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module linker

import os

// Host-only file output. The core (link_bytes, to_bytes, elf_bytes) never calls
// into this file, and every body here is compiled out under -freestanding, so
// the core stays free of libc file I/O.

// C.open declares the C open symbol used by the linker.
fn C.open(charptr, int, ...int) int

// C.write declares the C write symbol used by the linker.
fn C.write(int, voidptr, int) int

// C.close declares the C close symbol used by the linker.
fn C.close(int) int

// C.chmod declares the C chmod symbol used by the linker.
fn C.chmod(charptr, int) int

// C.rename declares the C rename symbol used by the linker.
fn C.rename(charptr, charptr) int

// The output file is created through the C library's open(), and the create and
// truncate bits are laid out differently per platform: the BSD family (and so
// macOS, the only target this linker was built for) uses 0x200/0x400, Linux
// 0x40/0x200 and MSVCRT 0x100/0x200. One constant only ever suits one of them;
// the others silently fail to create the file. MSVCRT also needs binary mode
// to preserve instruction bytes, including bytes equal to a newline.
const o_wronly_creat_trunc = $if windows {
	0x8301
} $else $if linux {
	0x241
} $else {
	0x601
}

// MSVCRT accepts read/write permission bits, without POSIX executable bits.
const output_file_permissions = $if windows { 0o600 } $else { 0o755 }

// write_executable publishes bytes at output_path through a temporary file, so a
// failed link never leaves a truncated executable behind.
fn write_executable(output_path string, bytes []u8) {
	$if freestanding {
		panic('the linker cannot write files in a freestanding build')
	} $else {
		tmp_output_path := '${output_path}.tmp.${os.getpid()}'
		if !write_output_file(tmp_output_path, bytes) {
			panic('failed to write output file')
		}
		if C.chmod(&char(tmp_output_path.str), output_file_permissions) != 0 {
			panic('failed to chmod output file')
		}
		if !replace_output_file(tmp_output_path, output_path) {
			panic('failed to rename output file')
		}
	}
}

// replace_output_file publishes the completed output using the host rename semantics.
fn replace_output_file(tmp_output_path string, output_path string) bool {
	$if freestanding {
		return false
	} $else {
		if C.rename(&char(tmp_output_path.str), &char(output_path.str)) == 0 {
			return true
		}
		$if windows {
			// MSVCRT rename cannot replace an existing destination. POSIX rename
			// already can, so its failure must preserve the previous output.
			C.remove(&char(output_path.str))
			return C.rename(&char(tmp_output_path.str), &char(output_path.str)) == 0
		}
		return false
	}
}

// write_output_file writes data to path, creating or truncating it.
pub fn write_output_file(path string, data []u8) bool {
	$if freestanding {
		return false
	} $else {
		fd := C.open(&char(path.str), o_wronly_creat_trunc, output_file_permissions)
		if fd < 0 {
			return false
		}
		if data.len > 0 {
			written := C.write(fd, data.data, data.len)
			if written != data.len {
				C.close(fd)
				return false
			}
		}
		return C.close(fd) == 0
	}
}
