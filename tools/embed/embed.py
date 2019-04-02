'''
Copyright (C) 2018-2019 Eagle Eye Networks

SPDX-License-Identifier: Apache-2.0
'''

import sys

INCLUDES = """
#include <stddef.h>
#include <string.h>
#include <stdio.h>
"""

STRUCT_HEAD = """
const struct embedded_file {
    const char *name;
    const unsigned char *data;
    size_t size;
} embedded_files[] = {
"""

STRUCT_TAIL = """  {NULL, NULL, 0}\n};\n"""

FUNCTION = """
const char *embed_file_get_content(const char *name, size_t *size) {
    const struct embedded_file *p;
    for (p = embedded_files; p->name != NULL; p++) {
        if (!strcmp(p->name, name)) {
            if (size != NULL) { *size = p->size; }
            return (const char *) p->data;
        }
    }
    return NULL;
}
"""

FUNCTION2 = """
void embed_file_print_all() {
    const struct embedded_file *p;
    for (p = embedded_files; p->name != NULL; p++) {
        printf("%s:\\n%s\\n", p->name, p->data);
    }
}
"""

def convert_file(file_name, index):
    i = 0
    result = "static const unsigned char v%d[] = {" % (index)
    with open(file_name, 'r') as fp:
        while 1:
            byte_s = fp.read(1)
            if not byte_s:
                break
            if i % 12 == 0:
                result += "\n "
            result += " 0x{:02x},".format(ord(byte_s))
            i = i + 1
    result += " 0x00\n};\n"
    return result

if __name__ == '__main__':
    index = 1
    struct = STRUCT_HEAD
    for file_name in sys.argv[1:]:
        print(convert_file(file_name, index))
        struct += '  {"%s", v%d, sizeof(v%d) - 1},\n' % (file_name, index, index)
        index = index + 1

    struct += STRUCT_TAIL
    print(INCLUDES)
    print(struct)
    print(FUNCTION)
    print(FUNCTION2)
