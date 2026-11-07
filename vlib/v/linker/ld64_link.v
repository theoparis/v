module linker

// Mini ld64: lays the parsed arm64 objects out in the single-object form that
// Linker expects, resolves symbols and relocations, then lets Linker emit the
// executable (load commands, stubs, GOT, bind info, code signature).

// Regions of the merged object. Linker places text, then str, then data.
const ld_kind_none = 0
const ld_kind_text = 1 // __TEXT,__text: MachOObject.text_data, symbols in sect 1
const ld_kind_str = 2 // other __TEXT data: MachOObject.str_data, symbols in sect 2
const ld_kind_data = 3 // __DATA*: MachOObject.data_data, symbols in sect 3

// LinkInput is one command-line file: an object (.o) or an archive (.a).
pub struct LinkInput {
pub:
	path string
	data []u8
}

// LinkOptions describes one link.
pub struct LinkOptions {
pub:
	ident      string // code-signature identifier
	entry      string = '_main'
	frameworks []string
	inputs     []LinkInput
}

// Placement says where a kept input section landed.
struct Placement {
	kind int
	off  int // offset within its region's bytes
}

// PointerFixup is an absolute 64-bit pointer in a non-text region. Its value
// depends on final addresses, so it is patched after the first layout pass.
struct PointerFixup {
	kind   int
	off    int
	target int
}

// Slot is a symbol's region and its value in the merged object's convention.
struct Slot {
	kind  int
	value u64
}

// link_executable links the inputs and returns the bytes of an arm64 executable.
pub fn link_executable(opts LinkOptions) ![]u8 {
	if opts.inputs.len == 0 {
		return error('no input files')
	}
	mut eager := []ObjectFile{}
	mut lazy := []ObjectFile{}
	for input in opts.inputs {
		if is_archive(input.data) {
			members := read_archive(input.path, input.data)!
			lazy << members
		} else {
			eager << parse_object(input.path, input.data)!
		}
	}
	objs := select_members(eager, lazy, opts.entry)
	return build_executable(objs, opts)
}

// select_members keeps every object given directly, plus the archive members
// needed to satisfy undefined globals, iterating to a fixed point (ld64 rules).
fn select_members(eager []ObjectFile, lazy []ObjectFile, entry string) []ObjectFile {
	mut defined := map[string]bool{}
	mut undefined := map[string]bool{}
	for o in eager {
		note_globals(o, mut defined, mut undefined)
	}
	if entry !in defined {
		undefined[entry] = true
	}
	mut taken := []bool{len: lazy.len}
	mut picked := []ObjectFile{}
	for {
		mut progress := false
		for i, m in lazy {
			if taken[i] || !defines_any(m, undefined) {
				continue
			}
			taken[i] = true
			progress = true
			picked << m
			note_globals(m, mut defined, mut undefined)
		}
		if !progress {
			break
		}
	}
	mut out := eager.clone()
	out << picked
	return out
}

fn is_global_def(s ObjSymbol) bool {
	return (s.type_ & ld_n_ext) != 0 && (s.type_ & ld_n_pext) == 0 && (s.type_ & ld_n_stab) == 0 &&
		(s.type_ & ld_n_type) == ld_n_sect && s.sect != 0
}

fn is_global_undef(s ObjSymbol) bool {
	return (s.type_ & ld_n_ext) != 0 && (s.type_ & ld_n_stab) == 0 &&
		(s.type_ & ld_n_type) == ld_n_undf && s.sect == 0 && s.name != ''
}

fn note_globals(o ObjectFile, mut defined map[string]bool, mut undefined map[string]bool) {
	for s in o.symbols {
		if is_global_def(s) {
			defined[s.name] = true
			undefined.delete(s.name)
		}
	}
	for s in o.symbols {
		if is_global_undef(s) && s.name !in defined {
			undefined[s.name] = true
		}
	}
}

fn defines_any(o ObjectFile, undefined map[string]bool) bool {
	for s in o.symbols {
		if is_global_def(s) && s.name in undefined {
			return true
		}
	}
	return false
}

// build_executable does the merge and runs Linker twice: once to learn the
// final addresses, then again after pointer fixups are written into the data.
fn build_executable(objs []ObjectFile, opts LinkOptions) ![]u8 {
	// 1. Place every kept section into its region, in command-line order.
	mut places := [][]Placement{}
	mut text_len := 0
	mut str_len := 0
	mut data_len := 0
	for o in objs {
		mut ps := []Placement{len: o.sections.len}
		for si, sec in o.sections {
			kind := classify_section(o.path, sec)!
			if kind == ld_kind_none {
				continue
			}
			if sec.align > 14 {
				return error('${o.path}: section ${sec.sectname} has an alignment that is too large')
			}
			align := 1 << int(sec.align)
			size := int(sec.size)
			if kind == ld_kind_text {
				if align > 16 {
					return error('${o.path}: __text alignment above 16 is not supported')
				}
				text_len = align_up(text_len, align)
				ps[si] = Placement{
					kind: kind
					off:  text_len
				}
				text_len += size
			} else if kind == ld_kind_str {
				if align > 16 {
					return error('${o.path}: ${sec.sectname} alignment above 16 is not supported')
				}
				str_len = align_up(str_len, align)
				ps[si] = Placement{
					kind: kind
					off:  str_len
				}
				str_len += size
			} else {
				data_len = align_up(data_len, align)
				ps[si] = Placement{
					kind: kind
					off:  data_len
				}
				data_len += size
			}
		}
		places << ps
	}
	// Object-space bases, using the same conventions as MachOObject.write():
	// sect 1 values are text offsets, sect 2 values start at the text length,
	// and sect 3 values start at data_base.
	str_base := align_up(text_len, 16)
	data_base := align_up(str_base + str_len, 8)

	// 2. Copy section bytes into the regions. Zero-fill bytes stay zero.
	mut text_bytes := []u8{len: str_base}
	mut str_bytes := []u8{len: str_len}
	mut data_bytes := []u8{len: data_len}
	for oi, o in objs {
		for si, sec in o.sections {
			p := places[oi][si]
			if p.kind == ld_kind_none || sec.data.len == 0 {
				continue
			}
			if p.kind == ld_kind_text {
				put_bytes(mut text_bytes, p.off, sec.data)
			} else if p.kind == ld_kind_str {
				put_bytes(mut str_bytes, p.off, sec.data)
			} else {
				put_bytes(mut data_bytes, p.off, sec.data)
			}
		}
	}

	// 3. Symbols. Globals are merged by name. File-local symbols get a per-object name.
	mut syms := []Symbol{}
	mut gmap := map[string]int{}
	mut gpath := map[string]string{}
	mut symmap := [][]int{}
	for o in objs {
		symmap << []int{len: o.symbols.len, init: -1}
	}
	for oi, o in objs {
		for s in o.symbols {
			if (s.type_ & ld_n_stab) != 0 || (s.type_ & ld_n_ext) == 0 || (s.type_ & ld_n_pext) != 0 {
				continue
			}
			if (s.type_ & ld_n_type) == ld_n_sect {
				si := int(s.sect) - 1
				if s.sect == 0 || si >= o.sections.len {
					return error('${o.path}: symbol ${s.name} has a bad section index')
				}
				p := places[oi][si]
				if p.kind == ld_kind_none {
					continue
				}
				sl := symbol_slot(o.path, o.sections[si], p, s, str_base, data_base)!
				new_sym := Symbol{
					name:  s.name
					type_: u8(ld_n_sect | ld_n_ext)
					sect:  u8(sl.kind)
					desc:  s.desc
					value: sl.value
				}
				if idx := gmap[s.name] {
					ex := syms[idx]
					if ex.sect == 0 || (is_weak(ex) && !is_weak(new_sym)) {
						syms[idx] = new_sym
						gpath[s.name] = o.path
					} else if !is_weak(ex) && !is_weak(new_sym) {
						return error("duplicate symbol '${s.name}' in:\n    ${gpath[s.name]}\n    ${o.path}")
					}
				} else {
					gmap[s.name] = syms.len
					gpath[s.name] = o.path
					syms << new_sym
				}
			} else if (s.type_ & ld_n_type) == ld_n_undf {
				if s.value != 0 {
					return error("common symbol '${s.name}' is not supported; compile with -fno-common")
				}
				if s.name !in gmap {
					gmap[s.name] = syms.len
					syms << Symbol{
						name:  s.name
						type_: u8(ld_n_ext)
						sect:  0
						desc:  s.desc
						value: 0
					}
				}
			} else {
				return error('${o.path}: absolute symbol ${s.name} is not supported')
			}
		}
	}
	// Every global occurrence maps to its merged symbol, by name.
	for oi, o in objs {
		for si, s in o.symbols {
			if (s.type_ & ld_n_stab) == 0 && (s.type_ & ld_n_ext) != 0 && (s.type_ & ld_n_pext) == 0 {
				if idx := gmap[s.name] {
					symmap[oi][si] = idx
				}
			}
		}
	}
	// File-local symbols (static and private-extern definitions).
	for oi, o in objs {
		for si, s in o.symbols {
			if (s.type_ & ld_n_stab) != 0 {
				continue
			}
			if (s.type_ & ld_n_ext) != 0 && (s.type_ & ld_n_pext) == 0 {
				continue
			}
			if (s.type_ & ld_n_type) != ld_n_sect || s.sect == 0 || int(s.sect) > o.sections.len {
				continue
			}
			si_sec := int(s.sect) - 1
			p := places[oi][si_sec]
			if p.kind == ld_kind_none {
				continue
			}
			sl := symbol_slot(o.path, o.sections[si_sec], p, s, str_base, data_base)!
			symmap[oi][si] = syms.len
			syms << Symbol{
				name:  '${s.name}@${oi}'
				type_: u8(ld_n_sect)
				sect:  u8(sl.kind)
				desc:  s.desc
				value: sl.value
			}
		}
	}

	// 4. Relocations. Text relocations go to Linker. Pointer relocations in
	// str and data are recorded as fixups for the second pass.
	mut m := MachOObject.new()
	mut fixups := []PointerFixup{}
	mut synth := map[string]int{}
	for oi, o in objs {
		for si, sec in o.sections {
			p := places[oi][si]
			if p.kind == ld_kind_none || sec.relocs.len == 0 {
				continue
			}
			mut pending := u64(0) // from ARM64_RELOC_ADDEND, applies to the next reloc
			for r in sec.relocs {
				if r.type_ == ld_reloc_addend {
					pending = u64(r.symnum)
					continue
				}
				if !r.extern {
					return error('${o.path}: section-relative relocation in ${sec.segname},${sec.sectname} is not supported')
				}
				if int(r.symnum) >= o.symbols.len {
					return error('${o.path}: relocation refers to symbol index ${r.symnum}, which is out of range')
				}
				mut target := symmap[oi][int(r.symnum)]
				if target < 0 {
					return error('${o.path}: relocation against ${o.symbols[int(r.symnum)].name}, which lives in a discarded section')
				}
				if pending != 0 {
					target = synthetic_addend(mut syms, mut synth, target, pending)!
					pending = 0
				}
				rtype := int(r.type_)
				off := p.off + int(r.addr)
				if p.kind == ld_kind_text {
					defined := syms[target].sect != 0
					mut new_type := rtype
					if rtype == arm64_reloc_got_load_page21 && defined {
						// ADRP to the GOT entry becomes ADRP to the symbol itself.
						new_type = arm64_reloc_page21
					} else if rtype == arm64_reloc_got_load_pageoff12 && defined {
						// LDR Xt, [Xn, GOT@PAGEOFF] becomes ADD Xt, Xn, PAGEOFF.
						instr := rd_u32(text_bytes, off)!
						if (instr & 0xFFC00000) != 0xF9400000 {
							return error('${o.path}: GOT load that is not a 64-bit LDR cannot be relaxed')
						}
						put_u32_le(mut text_bytes, off, (instr & 0x003FFFFF) | 0x91000000)
						new_type = arm64_reloc_pageoff12
					} else if rtype != arm64_reloc_branch26 && rtype != arm64_reloc_page21 && rtype != arm64_reloc_pageoff12 && rtype != arm64_reloc_got_load_page21 && rtype != arm64_reloc_got_load_pageoff12 {
						return error('${o.path}: relocation type ${rtype} in __text is not supported')
					}
					m.relocs << RelocationInfo{
						addr:    off
						sym_idx: target
						pcrel:   r.pcrel
						length:  2
						extern:  true
						type_:   new_type
					}
				} else {
					if rtype != ld_reloc_unsigned || r.length != 3 {
						return error('${o.path}: relocation type ${rtype} in ${sec.sectname} is not supported (only 64-bit pointers)')
					}
					fixups << PointerFixup{
						kind:   p.kind
						off:    off
						target: target
					}
				}
			}
		}
	}

	entry_idx := gmap[opts.entry] or { -1 }
	if entry_idx < 0 || syms[entry_idx].sect != 1 {
		return error('undefined symbol: ${opts.entry}')
	}

	// Anchor for Linker's data-base computation (it uses the lowest sect-3 value).
	syms << Symbol{
		name:  'l_ld64_data_base'
		type_: u8(ld_n_sect)
		sect:  3
		value: u64(data_base)
	}

	m.text_data = text_bytes
	m.str_data = str_bytes
	m.data_data = data_bytes
	m.symbols = syms

	// 5. First layout pass: addresses don't depend on the bytes, only on sizes.
	mut layout := Linker.new(m)
	layout.frameworks = opts.frameworks
	layout.link_bytes(opts.ident, opts.entry)
	for f in fixups {
		t := syms[f.target]
		if t.sect == 0 {
			return error("undefined symbol '${t.name}' is referenced from a pointer; it must be defined")
		}
		target_addr := sym_address(layout, t, data_base)
		if f.kind == ld_kind_str {
			addend := rd_u64(m.str_data, f.off)!
			put_u64_le(mut m.str_data, f.off, target_addr + addend)
		} else {
			addend := rd_u64(m.data_data, f.off)!
			put_u64_le(mut m.data_data, f.off, target_addr + addend)
		}
	}

	// 6. Second pass: the real executable.
	mut exe := Linker.new(m)
	exe.frameworks = opts.frameworks
	return exe.link_bytes(opts.ident, opts.entry)
}

fn classify_section(path string, sec ObjSection) !int {
	mut kind := ld_kind_none
	if sec.segname == '__TEXT' {
		if sec.sectname == '__text' {
			kind = ld_kind_text
		} else if sec.sectname == '__eh_frame' || sec.sectname == '__unwind_info' ||
			sec.sectname == '__compact_unwind' {
			kind = ld_kind_none
		} else {
			kind = ld_kind_str
		}
	} else if sec.segname == '__DATA' || sec.segname == '__DATA_CONST' {
		kind = ld_kind_data
	}
	if kind == ld_kind_none {
		return kind
	}
	sect_type := sec.flags & 0xff
	if sect_type == ld_sect_tls_regular || sect_type == ld_sect_tls_zerofill ||
		sect_type == ld_sect_tls_variables || sect_type == ld_sect_tls_init_fp {
		return error('${path}: thread-local section ${sec.segname},${sec.sectname} is not supported')
	}
	return kind
}

// symbol_slot maps a symbol defined in a kept section to its region and its
// value in the merged object's convention.
fn symbol_slot(path string, sec ObjSection, p Placement, s ObjSymbol, str_base int, data_base int) !Slot {
	if s.value < sec.addr {
		return error('${path}: symbol ${s.name} lies before its section')
	}
	within := p.off + int(s.value - sec.addr)
	if p.kind == ld_kind_text {
		return Slot{
			kind:  p.kind
			value: u64(within)
		}
	}
	if p.kind == ld_kind_str {
		return Slot{
			kind:  p.kind
			value: u64(str_base + within)
		}
	}
	return Slot{
		kind:  p.kind
		value: u64(data_base + within)
	}
}

fn is_weak(s Symbol) bool {
	return (s.desc & ld_n_weak_def) != 0
}

// synthetic_addend returns a file-local symbol at target+addend, for relocations
// preceded by ARM64_RELOC_ADDEND. Linker has no addend field, so the addend is
// folded into the symbol it points at.
fn synthetic_addend(mut syms []Symbol, mut cache map[string]int, target int, addend u64) !int {
	t := syms[target]
	if t.sect == 0 {
		return error("addend applied to undefined symbol '${t.name}' is not supported")
	}
	key := '${t.name}+${addend}'
	if idx := cache[key] {
		return idx
	}
	idx := syms.len
	syms << Symbol{
		name:  key
		type_: u8(ld_n_sect)
		sect:  t.sect
		desc:  0
		value: t.value + addend
	}
	cache[key] = idx
	return idx
}

// sym_address returns the final virtual address Linker gives a merged symbol.
fn sym_address(l &Linker, s Symbol, data_base int) u64 {
	if s.sect == 3 {
		return l.data_vmaddr + (s.value - u64(data_base))
	}
	return l.text_vmaddr + u64(l.code_start) + s.value
}

fn align_up(v int, a int) int {
	return (v + a - 1) / a * a
}

fn put_bytes(mut dst []u8, off int, src []u8) {
	for i, b in src {
		dst[off + i] = b
	}
}

fn put_u32_le(mut dst []u8, off int, v u32) {
	for i in 0 .. 4 {
		shift := u32(8 * i)
		dst[off + i] = u8(v >> shift)
	}
}

fn put_u64_le(mut dst []u8, off int, v u64) {
	for i in 0 .. 8 {
		shift := u64(8 * i)
		dst[off + i] = u8(v >> shift)
	}
}
