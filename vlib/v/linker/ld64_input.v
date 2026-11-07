module linker

// Input side of the mini ld64: reads arm64 MH_OBJECT files and ar(1) archives
// into section, symbol and relocation tables. ld64_link.v lays them out.

const ld_magic_64 = u32(0xfeedfacf)
const ld_filetype_object = u32(1)
const ld_cputype_arm64 = u32(0x0100000c)
const ld_cmd_segment_64 = u32(0x19)
const ld_cmd_symtab = u32(0x02)
const ld_sect_header_size = 80
const ld_nlist_size = 16
const ld_reloc_size = 8

// n_type / n_desc bits (mach-o/nlist.h)
const ld_n_stab = 0xe0
const ld_n_pext = 0x10
const ld_n_type = 0x0e
const ld_n_undf = 0x00
const ld_n_sect = 0x0e
const ld_n_ext = 0x01
const ld_n_weak_def = 0x80

// section type (low byte of flags)
const ld_sect_zerofill = 0x01
const ld_sect_gb_zerofill = 0x0c
const ld_sect_tls_regular = 0x11
const ld_sect_tls_zerofill = 0x12
const ld_sect_tls_variables = 0x13
const ld_sect_tls_init_fp = 0x15

// relocation types beyond the ones link/macho.v names
const ld_reloc_unsigned = 0
const ld_reloc_addend = 10

// ObjReloc is one relocation_info entry.
struct ObjReloc {
	addr   u32
	symnum u32
	pcrel  bool
	length u8
	extern bool
	type_  u8
}

// ObjSection is one section of an input object. data is empty for zero-fill sections.
struct ObjSection {
	segname  string
	sectname string
	addr     u64
	size     u64
	align    u32 // log2
	flags    u32
	data     []u8
	relocs   []ObjReloc
}

// ObjSymbol is one nlist_64 entry.
struct ObjSymbol {
	name  string
	type_ u8
	sect  u8 // 1-based section ordinal, 0 = none
	desc  u16
	value u64
}

// ObjectFile is a parsed MH_OBJECT.
struct ObjectFile {
	path     string
	sections []ObjSection
	symbols  []ObjSymbol
}

fn rd_u16(d []u8, off int) !u16 {
	if off < 0 || off + 2 > d.len {
		return error('truncated Mach-O data')
	}
	return u16(d[off]) | (u16(d[off + 1]) << 8)
}

fn rd_u32(d []u8, off int) !u32 {
	if off < 0 || off + 4 > d.len {
		return error('truncated Mach-O data')
	}
	return u32(d[off]) | (u32(d[off + 1]) << 8) | (u32(d[off + 2]) << 16) | (u32(d[off + 3]) << 24)
}

fn rd_u64(d []u8, off int) !u64 {
	lo := rd_u32(d, off)!
	hi := rd_u32(d, off + 4)!
	return u64(lo) | (u64(hi) << 32)
}

// fixed_name reads a 16-byte, NUL-padded segment or section name.
fn fixed_name(d []u8, off int) string {
	mut end := off
	for end < off + 16 && end < d.len && d[end] != 0 {
		end++
	}
	return d[off..end].bytestr()
}

fn cstr_at(d []u8, off int) !string {
	if off < 0 || off >= d.len {
		return error('string table offset out of range')
	}
	mut end := off
	for end < d.len && d[end] != 0 {
		end++
	}
	return d[off..end].bytestr()
}

// is_object reports whether d starts with the 64-bit little-endian Mach-O magic.
fn is_object(d []u8) bool {
	if d.len < 4 {
		return false
	}
	magic := rd_u32(d, 0) or { u32(0) }
	return magic == ld_magic_64
}

// parse_object reads one arm64 MH_OBJECT file.
fn parse_object(path string, d []u8) !ObjectFile {
	if !is_object(d) || d.len < 32 {
		return error('${path}: not a 64-bit Mach-O object file')
	}
	cputype := rd_u32(d, 4)!
	filetype := rd_u32(d, 12)!
	if cputype != ld_cputype_arm64 {
		return error('${path}: built for cputype 0x${cputype.hex()}, but only arm64 can be linked')
	}
	if filetype != ld_filetype_object {
		return error('${path}: not a relocatable object (MH_OBJECT); dylibs and executables cannot be linked as inputs')
	}
	ncmds := int(rd_u32(d, 16)!)
	mut sections := []ObjSection{}
	mut symoff := 0
	mut nsyms := 0
	mut stroff := 0
	mut off := 32
	for _ in 0 .. ncmds {
		cmd := rd_u32(d, off)!
		cmdsize := int(rd_u32(d, off + 4)!)
		if cmdsize < 8 || off + cmdsize > d.len {
			return error('${path}: malformed load command')
		}
		if cmd == ld_cmd_segment_64 {
			nsects := int(rd_u32(d, off + 64)!)
			for i in 0 .. nsects {
				sections << read_section(path, d, off + 72 + i * ld_sect_header_size)!
			}
		} else if cmd == ld_cmd_symtab {
			symoff = int(rd_u32(d, off + 8)!)
			nsyms = int(rd_u32(d, off + 12)!)
			stroff = int(rd_u32(d, off + 16)!)
		}
		off += cmdsize
	}
	mut syms := []ObjSymbol{}
	if nsyms > 0 {
		if symoff + nsyms * ld_nlist_size > d.len {
			return error('${path}: symbol table past end of file')
		}
		for i in 0 .. nsyms {
			e := symoff + i * ld_nlist_size
			strx := int(rd_u32(d, e)!)
			name := cstr_at(d, stroff + strx)!
			syms << ObjSymbol{
				name:  name
				type_: d[e + 4]
				sect:  d[e + 5]
				desc:  rd_u16(d, e + 6)!
				value: rd_u64(d, e + 8)!
			}
		}
	}
	return ObjectFile{
		path:     path
		sections: sections
		symbols:  syms
	}
}

// read_section decodes one section_64 header and its contents and relocations.
fn read_section(path string, d []u8, s int) !ObjSection {
	flags := rd_u32(d, s + 64)!
	size := rd_u64(d, s + 40)!
	foff := int(rd_u32(d, s + 48)!)
	reloff := int(rd_u32(d, s + 56)!)
	nreloc := int(rd_u32(d, s + 60)!)
	sect_type := flags & 0xff
	zerofill := sect_type == ld_sect_zerofill || sect_type == ld_sect_gb_zerofill
	mut data := []u8{}
	if !zerofill {
		if u64(foff) + size > u64(d.len) {
			return error('${path}: section data past end of file')
		}
		data = d[foff..foff + int(size)].clone()
	}
	mut relocs := []ObjReloc{}
	for j in 0 .. nreloc {
		ro := reloff + j * ld_reloc_size
		addr := rd_u32(d, ro)!
		info := rd_u32(d, ro + 4)!
		relocs << ObjReloc{
			addr:   addr
			symnum: info & 0xffffff
			pcrel:  ((info >> 24) & 1) == 1
			length: u8((info >> 25) & 3)
			extern: ((info >> 27) & 1) == 1
			type_:  u8(info >> 28)
		}
	}
	return ObjSection{
		segname:  fixed_name(d, s + 16)
		sectname: fixed_name(d, s)
		addr:     rd_u64(d, s + 32)!
		size:     size
		align:    rd_u32(d, s + 52)!
		flags:    flags
		data:     data
		relocs:   relocs
	}
}

// is_archive reports whether d is an ar(1) archive ("!<arch>\n").
fn is_archive(d []u8) bool {
	return d.len >= 8 && d[0..8].bytestr() == '!<arch>\n'
}

// read_archive returns the arm64 object members of an ar archive. Non-object
// members (the symbol index, bitcode, ...) are skipped.
fn read_archive(path string, d []u8) ![]ObjectFile {
	mut objs := []ObjectFile{}
	mut names := []u8{} // GNU long-name table, the "//" member
	mut off := 8
	for off + 60 <= d.len {
		raw_name := d[off..off + 16].bytestr().trim_right(' ')
		disk_size := d[off + 48..off + 58].bytestr().trim_space().int()
		body_start := off + 60
		if disk_size < 0 || body_start + disk_size > d.len {
			return error('${path}: truncated archive member ${raw_name}')
		}
		next := body_start + disk_size + (disk_size % 2)
		mut name := raw_name
		mut data_start := body_start
		if name.starts_with('#1/') {
			// BSD: the member name is the first bytes of the body
			nlen := name[3..].int()
			if nlen < 0 || nlen > disk_size {
				return error('${path}: bad BSD archive name length')
			}
			name = d[body_start..body_start + nlen].bytestr().trim_right('\x00')
			data_start += nlen
		} else if name == '//' {
			names = d[body_start..body_start + disk_size].clone()
			off = next
			continue
		} else if name.len > 1 && name[0] == `/` && name[1] >= `0` && name[1] <= `9` {
			// GNU: name is an offset into the "//" table
			name = gnu_long_name(names, name[1..].int())
		}
		if name == '/' || name.starts_with('__.SYMDEF') {
			off = next
			continue
		}
		name = name.trim_right('/')
		body := d[data_start..body_start + disk_size]
		if is_object(body) {
			objs << parse_object('${path}(${name})', body)!
		}
		off = next
	}
	return objs
}

fn gnu_long_name(names []u8, at int) string {
	if at < 0 || at >= names.len {
		return ''
	}
	mut end := at
	for end < names.len && names[end] != `\n` {
		end++
	}
	return names[at..end].bytestr().trim_right('/')
}
