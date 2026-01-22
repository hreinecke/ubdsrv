#include <config.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <inttypes.h>
#include <stdio.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

#include <linux/ioctl.h>

#include "ublk_cmd.h"
#include "sheepdog_proto.h"
#include "sheep.h"

int connect_to_sheep(const char *addr, int port)
{
	char portstr[16];
	int sock;
	struct addrinfo hints;
	struct addrinfo *ai = NULL;
	struct addrinfo *rp = NULL;
	int e;

	sprintf(portstr, "%d", port);
	memset(&hints,'\0',sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
	hints.ai_protocol = IPPROTO_TCP;

	e = getaddrinfo(addr, portstr, &hints, &ai);

	if(e != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(e));
		freeaddrinfo(ai);
		return -1;
	}

	for(rp = ai; rp != NULL; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if(sock == -1)
			continue;	/* error */

		if(connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
			break;		/* success */
			
		close(sock);
	}

	if (rp == NULL) {
		sock = -1;
		goto err;
	}

	e = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &e, sizeof(int));
err:
	freeaddrinfo(ai);
	return sock;
}

static int sheepdog_submit(int fd, struct sd_req *req, const void *buf,
			   struct sd_rsp *rsp)
{
	size_t buflen = req->data_length;
	int ret;

	ret = write(fd, req, sizeof(*req));
	if (ret != sizeof(req))
		return -EIO;
	if (buf) {
		ret = write(fd, buf, buflen);
		if (ret != buflen)
			return -EIO;
	}
	ret = read(fd, rsp, sizeof(*rsp));
	if (ret != sizeof(*rsp))
		return -EIO;

	return 0;
}

/* --- Sheepdog Protocol Handshake --- */

int sheepdog_vdi_lookup(int fd, const char *name, uint32_t *vid)
{
	struct sd_req req = {0};
	struct sd_rsp rsp = {0};
	size_t buflen = SD_MAX_VDI_LEN;
	char name_buf[SD_MAX_VDI_LEN] = {0};
	int ret;

	req.opcode = SD_OP_GET_VDI_INFO;
	req.data_length = buflen;
	req.flags = SD_FLAG_CMD_WRITE;
	strncpy(name_buf, name, strlen(name));

	ret = sheepdog_submit(fd, &req, name, &rsp);
	if (ret < 0)
		return ret;
	if (rsp.result != SD_RES_SUCCESS)
		return -ENOENT;

	*vid = rsp.vdi.vdi_id;
	return 0;
}

int sheepdog_read_params(int fd, uint32_t vdi_id, struct ublk_params *p)
{
	struct sd_req req = {0};
	struct sd_rsp rsp = {0};
	struct sd_inode inode = { 0 };
	int ret;

	req.opcode = SD_OP_READ_OBJ;
	req.data_length = SD_INODE_SIZE;
	req.obj.oid = vid_to_vdi_oid(vdi_id);
	req.obj.offset = 0;
	ret = sheepdog_submit(fd, &req, &inode, &rsp);
	if (ret < 0)
		return ret;
	if (rsp.result != SD_RES_SUCCESS)
		return -ENOENT;
	p->basic.chunk_sectors =
		(uint32_t)(1 << (inode.block_size_shift - 9));
	p->basic.physical_bs_shift = inode.block_size_shift;
	p->basic.dev_sectors = inode.vdi_size >> 9;
	return rsp.result != SD_RES_SUCCESS ? -ENOENT : 0;
}

