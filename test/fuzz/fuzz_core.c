#include <rz_core.h>
#include <rz_analysis.h>

LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	int perms = RZ_PERM_RX;
	ut64 mapaddr = 0LL;
	RzCore *r = rz_core_new();
	char *path = rz_str_newf("malloc://%zu", Size);
	RzCoreFile *fh = rz_core_file_open(r, path, perms, mapaddr);
	rz_io_map_new(r->io, fh->fd, 7, 0LL, mapaddr,
		rz_io_fd_size(r->io, fh->fd));
	rz_io_write_at(r->io, mapaddr, (const ut8 *)Data, Size);
	rz_core_block_read(r);
	return 0; // Non-zero return values are reserved for future use.
}