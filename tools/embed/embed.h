/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef EMBED_H__
#define EMBED_H__

#ifdef __cplusplus
extern "C" {
#endif

const char *embed_file_get_content(const char *file_name, size_t *size);
void embed_file_print_all();

#ifdef __cplusplus
}
#endif

#endif /* EMBED_H__ */

