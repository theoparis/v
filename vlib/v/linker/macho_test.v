module linker

fn test_native_main_stack_matches_macos_c_backend() {
	mut ld := Linker.new(MachOObject.new())
	ld.write_main_cmd(4096)
	assert read_u32_le(ld.buf, 0) == lc_main
	assert read_u32_le(ld.buf, 8) == 4096
	assert read_u32_le(ld.buf, 16) == 64 * 1024 * 1024
	assert read_u32_le(ld.buf, 20) == 0
}

// test_object_data_section_starts_on_an_8_byte_boundary checks that __data is padded
// after an odd-sized __cstring, because gen.v places data symbols at the aligned address.
fn test_object_data_section_starts_on_an_8_byte_boundary() {
	mut m := MachOObject.new()
	m.text_data = []u8{len: 8}
	m.str_data = 'abc'.bytes()
	m.data_data = [u8(0xd1), 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8]
	bytes := m.to_bytes()
	// Section headers follow the 32-byte header and the 72-byte segment command.
	// The data header is the third section: text, cstring, data.
	data_header := 32 + 72 + 80 * 2
	assert read_u32_le(bytes, data_header + 32) == 16 // addr: 8 (text) + 3 (cstring) + 5 pad
	assert read_u32_le(bytes, data_header + 36) == 0
	file_off := int(read_u32_le(bytes, data_header + 48))
	assert file_off % 8 == 0
	assert bytes[file_off..file_off + 8] == m.data_data
}
