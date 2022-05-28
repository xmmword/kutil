/*
 * Copyright (C) 2022 xmmword
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __KUTIL_H
#define __KUTIL_H

#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>


/*
    *    src/kutil.h
    *    Date: 05/28/22
    *    Author: @xmmword
*/


/* Node struct for our linked list! */
typedef struct _node {
  int32_t index;
  uint8_t *token;
  struct _node *next;
} token_t;

/* Struct for /proc/kallsyms entries! */
typedef struct _syscall {
  uint64_t addr;
  uint8_t symbol[BUFSIZ];
  uint8_t kmodule[BUFSIZ];
  uint8_t symbol_type[16];
} syscall_t;

/* Struct for /proc/modules entries! */
typedef struct _kmodule {
  uint64_t size;
  uint64_t offset;
  int32_t instances;
  uint8_t state[BUFSIZ];
  uint8_t kmodule[BUFSIZ];
  uint8_t dependencies[BUFSIZ];
} kmodule_t;

static void print_help(void);
void print_formatted_messages(token_t *head);

void kutil_log(const uint8_t *message, ...);
void print_module_information(const kmodule_t *module);

token_t *return_parsed_messages(const uint8_t *log);
kmodule_t *parse_loaded_module_data(kmodule_t *information, const uint8_t *string);
syscall_t *parse_kernel_symbol_information(syscall_t *information, const uint8_t *string);

bool read_kernel_logs(void);
bool fetch_module_data(const uint8_t *module_name);

bool iterate_kernel_symbols(const uint8_t *driver);
syscall_t *resolve_kernel_symbol(const uint8_t *kernel_symbol);

bool remove_kernel_module(const uint8_t *module_name);
bool insert_kernel_module(const uint8_t *params, const uint8_t *module_path);
bool invoke_finite_module(const uint8_t *params, const uint8_t *module_path);

void delete_token(token_t **head, const int32_t index);
void append_token(token_t **head, const int32_t index, const uint8_t *token);

bool handle_arguments(const int32_t argc, const int8_t **argv);

#endif