/*
 * Taken and modified from git by Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>

#include "ublksrv.h"
#include "ublksrv_utils.h"
#include "util.h"

mode_t sd_def_dmode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
mode_t sd_def_fmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

static ssize_t _read(int fd, void *buf, size_t len)
{
	ssize_t nr;
	while (true) {
		nr = read(fd, buf, len);
		if (unlikely(nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

static ssize_t _write(int fd, const void *buf, size_t len)
{
	ssize_t nr;
	while (true) {
		nr = write(fd, buf, len);
		if (unlikely(nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

ssize_t xread(int fd, void *buf, size_t count)
{
	char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t loaded = _read(fd, p, count);
		if (unlikely(loaded < 0))
			return -1;
		if (unlikely(loaded == 0))
			return total;
		count -= loaded;
		p += loaded;
		total += loaded;
	}

	return total;
}

ssize_t xwrite(int fd, const void *buf, size_t count)
{
	const char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t written = _write(fd, p, count);
		if (unlikely(written < 0))
			return -1;
		if (unlikely(!written)) {
			errno = ENOSPC;
			return -1;
		}
		count -= written;
		p += written;
		total += written;
	}

	return total;
}

static ssize_t _pread(int fd, void *buf, size_t len, off_t offset)
{
	ssize_t nr;
	while (true) {
		nr = pread(fd, buf, len, offset);
		if (unlikely(nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

static ssize_t _pwrite(int fd, const void *buf, size_t len, off_t offset)
{
	ssize_t nr;
	while (true) {
		nr = pwrite(fd, buf, len, offset);
		if (unlikely(nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

ssize_t xpread(int fd, void *buf, size_t count, off_t offset)
{
	char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t loaded = _pread(fd, p, count, offset);
		if (unlikely(loaded < 0))
			return -1;
		if (unlikely(loaded == 0))
			return total;
		count -= loaded;
		p += loaded;
		total += loaded;
		offset += loaded;
	}

	return total;
}

ssize_t xpwrite(int fd, const void *buf, size_t count, off_t offset)
{
	const char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t written = _pwrite(fd, p, count, offset);
		if (unlikely(written < 0))
			return -1;
		if (unlikely(!written)) {
			errno = ENOSPC;
			return -1;
		}
		count -= written;
		p += written;
		total += written;
		offset += written;
	}

	return total;
}

/*
 * Return the read value on success, or -1 if efd has been made nonblocking and
 * errno is EAGAIN.  If efd has been marked blocking or the eventfd counter is
 * not zero, this function doesn't return error.
 */
int eventfd_xread(int efd)
{
	int ret;
	eventfd_t value = 0;

	do {
		ret = eventfd_read(efd, &value);
	} while (unlikely(ret < 0) && errno == EINTR);

	if (ret == 0)
		ret = value;
	else if (unlikely(errno != EAGAIN))
		ublk_err("%s: eventfd_read() failed, %m", __func__);

	return ret;
}

void eventfd_xwrite(int efd, int value)
{
	int ret;

	do {
		ret = eventfd_write(efd, (eventfd_t)value);
	} while (unlikely(ret < 0) && (errno == EINTR || errno == EAGAIN));

	if (unlikely(ret < 0))
		ublk_err("%s: eventfd_write() failed, %m", __func__);
}

/*
 * Copy the string str to buf. If str length is bigger than buf_size -
 * 1 then it is clamped to buf_size - 1.
 * NOTE: this function does what strncpy should have done to be
 * useful. NEVER use strncpy.
 *
 * @param buf destination buffer
 * @param buf_size size of destination buffer
 * @param str source string
 */
void pstrcpy(char *buf, int buf_size, const char *str)
{
	int c;
	char *q = buf;

	if (buf_size <= 0)
		return;

	while (true) {
		c = *str++;
		if (c == 0 || q >= buf + buf_size - 1)
			break;
		*q++ = c;
	}
	*q = '\0';
}

/*
 * Find zero blocks from the beginning and end of buffer
 *
 * The caller passes the offset of 'buf' with 'poffset' so that this function
 * can align the return values to BLOCK_SIZE.  'plen' points the length of the
 * buffer.  If there are zero blocks at the beginning of the buffer, this
 * function increases the offset and decreases the length on condition that
 * '*poffset' is block-aligned.  If there are zero blocks at the end of the
 * buffer, this function also decreases the length on condition that '*plen' is
 * block-aligned.
 */
void find_zero_blocks(const void *buf, uint64_t *poffset, uint32_t *plen)
{
	const uint8_t zero[BLOCK_SIZE] = {0};
	const uint8_t *p = buf;
	uint64_t start = *poffset;
	uint64_t offset = 0;
	uint32_t len = *plen;

	/* trim zero blocks from the beginning of buffer */
	while (len >= BLOCK_SIZE) {
		size_t size = BLOCK_SIZE - (start + offset) % BLOCK_SIZE;

		if (memcmp(p + offset, zero, size) != 0)
			break;

		offset += size;
		len -= size;
	}

	/* trim zero sectors from the end of buffer */
	while (len >= BLOCK_SIZE) {
		size_t size = (start + offset + len) % BLOCK_SIZE;
		if (size == 0)
			size = BLOCK_SIZE;

		if (memcmp(p + offset + len - size, zero, size) != 0)
			break;

		len -= size;
	}

	*plen = len;
	*poffset = start + offset;
}

/*
 * Trim zero blocks from the beginning and end of buffer
 *
 * This function is similar to find_zero_blocks(), but this updates 'buf' so
 * that the zero block are removed from the beginning of buffer.
 */
void trim_zero_blocks(void *buf, uint64_t *poffset, uint32_t *plen)
{
	uint8_t *p = buf;
	uint64_t orig_offset = *poffset;

	find_zero_blocks(buf, poffset, plen);
	if (orig_offset < *poffset)
		memmove(p, p + *poffset - orig_offset, *plen);
}

/*
 * Convert a decimal string like as strtoll to uint32_t/uint16_t
 *
 * returns:
 *   - a converted value if success i.e. neither negative value nor overflow
 *   - undefined if something went wrong and set errno accordingly
 *
 * errno:
 *   - 0 if success
 *   - EINVAL if one of the following:
 *       - nptr was an empty string
 *       - there was an unconvertible character in nptr
 *   - ERANGE if negative/positive overflow occurred
 */
uint32_t str_to_u32(const char *nptr)
{
	char *endptr;
	errno = 0;
	const long long conv = strtoll(nptr, &endptr, 10);
	/* empty string or unconvertible character */
	if (nptr == endptr || *endptr != '\0') {
		errno = EINVAL;
		return (uint32_t)conv;
	}
	/* negative value or overflow */
	if (conv < 0LL || UINT32_MAX < conv) {
		errno = ERANGE;
		return UINT32_MAX;
	}
	return (uint32_t)conv;
}

uint16_t str_to_u16(const char *nptr)
{
	const uint32_t conv = str_to_u32(nptr);
	/* overflow */
	if (UINT16_MAX < conv) {
		errno = ERANGE;
		return UINT16_MAX;
	}
	return (uint16_t)conv;
}
