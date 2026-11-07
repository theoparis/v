module linker

// Unit tests for the mini ld64 input reader and merger. Run: v test link/

fn make_object(defs []string, undefs []string, calls []string) []u8 {
	mut m := MachOObject.new()
	// bl <calls[0]>; ret   (or just ret when there are no calls)
	m.text_data = [u8(0x00), 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6]
	for d in defs {
		m.add_symbol(d, 4, true, 1)
	}
	for u in undefs {
		m.add_undefined(u)
	}
	for c in calls {
		idx := m.add_undefined(c)
		m.add_reloc(0, idx, arm64_reloc_branch26, true)
	}
	return m.to_bytes()
}

fn pad_right(s string, n int) string {
	if s.len >= n {
		return s
	}
	return s + ' '.repeat(n - s.len)
}

fn ar_member(name string, body []u8) []u8 {
	mut out := []u8{}
	hdr := pad_right('${name}/', 16) + pad_right('0', 12) + pad_right('0', 6) + pad_right('0', 6) +
		pad_right('100644', 8) + pad_right('${body.len}', 10) + '\x60\x0a'
	out << hdr.bytes()
	out << body
	if body.len % 2 == 1 {
		out << u8(0x0a)
	}
	return out
}

fn test_parse_round_trip() {
	bytes := make_object(['_main'], ['_puts'], ['_puts'])
	obj := parse_object('rt.o', bytes) or { panic(err) }
	assert obj.symbols.len == 2
	assert obj.symbols[0].name == '_main'
	assert obj.symbols[0].sect == 1
	assert obj.symbols[1].name == '_puts'
	assert obj.symbols[1].sect == 0
	mut text := ObjSection{}
	for sec in obj.sections {
		if sec.sectname == '__text' {
			text = sec
		}
	}
	assert text.data.len == 8
	assert text.relocs.len == 1
	assert text.relocs[0].type_ == u8(arm64_reloc_branch26)
	assert text.relocs[0].symnum == 1
	assert text.relocs[0].extern
	assert text.relocs[0].pcrel
}

fn test_link_smoke() {
	bytes := make_object(['_main'], [], [])
	out := link_executable(LinkOptions{
		ident:  'smoke'
		inputs: [LinkInput{
			path: 'smoke.o'
			data: bytes
		}]
	}) or { panic(err) }
	assert out.len > 32
	assert out[0] == 0xcf
	assert out[1] == 0xfa
	assert out[2] == 0xed
	assert out[3] == 0xfe
}

fn test_duplicate_symbol_is_an_error() {
	a := make_object(['_main'], [], [])
	b := make_object(['_main'], [], [])
	mut msg := ''
	link_executable(LinkOptions{
		inputs: [LinkInput{
			path: 'a.o'
			data: a
		}, LinkInput{
			path: 'b.o'
			data: b
		}]
	}) or {
		msg = err.msg()
		[]u8{}
	}
	assert msg.contains("duplicate symbol '_main'")
}

fn test_archive_member_is_pulled_only_when_needed() {
	main_o := make_object(['_main'], [], ['_helper'])
	helper_o := make_object(['_helper'], [], [])
	unused_o := make_object(['_unused'], [], [])
	mut ar := '!<arch>\n'.bytes()
	ar << ar_member('helper.o', helper_o)
	ar << ar_member('unused.o', unused_o)
	eager := [parse_object('main.o', main_o) or { panic(err) }]
	lazy := read_archive('libx.a', ar) or { panic(err) }
	assert lazy.len == 2
	picked := select_members(eager, lazy, '_main')
	assert picked.len == 2
	assert picked[1].symbols[0].name == '_helper'
	out := link_executable(LinkOptions{
		inputs: [LinkInput{
			path: 'main.o'
			data: main_o
		}, LinkInput{
			path: 'libx.a'
			data: ar
		}]
	}) or { panic(err) }
	assert out.len > 32
}
