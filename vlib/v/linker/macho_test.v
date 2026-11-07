module linker

fn test_native_main_stack_matches_macos_c_backend() {
	mut ld := Linker.new(MachOObject.new())
	ld.write_main_cmd(4096)
	assert read_u32_le(ld.buf, 0) == lc_main
	assert read_u32_le(ld.buf, 8) == 4096
	assert read_u32_le(ld.buf, 16) == 64 * 1024 * 1024
	assert read_u32_le(ld.buf, 20) == 0
}
