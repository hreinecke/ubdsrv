// SPDX-License-Identifier: GPL-2.0

#ifndef __SHEEP_H__
#define __SHEEP_H__

#ifdef __cplusplus
extern "C" {
#endif

int connect_to_sheep(const char *addr, int port);
int sheepdog_vdi_lookup(int fd, const char *name, uint32_t *vid);
int sheepdog_read_params(int fd, uint32_t vdi_id, struct ublk_params *p);

#ifdef __cplusplus
}
#endif
#endif /* __SHEEP_H__ */
