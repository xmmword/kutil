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

#include "kutil.h"


/*
    *    src/kutil.c
    *    Date: 05/28/22
    *    Author: @xmmword
*/


/**
 * @brief Outputs a log.
 * @param message The message that will be printed to the screen.
 */

void kutil_log(const uint8_t *message, ...) {
  va_list arguments;

  va_start(arguments, message);
  printf("[kutil]: ");

  vprintf(message, arguments); 
  va_end(arguments);
}

/**
 * @brief Prints the available flags.
 */

static void print_help(void) {
  printf(
    "General Options:\n"
    "\t-h\t\t\t\t\tDisplays the available options\n"
    "\t-l\t\t\t\t\tRead logs from the kernel ring buffer\n"
    "\t-i <driver> [Optional: <parameters>]\tInsert a driver into kernel memory\n"
    "\t-r <driver>\t\t\t\tRemove a driver from kernel memory\n"
    "\t-s <driver>\t\t\t\tFetches information about the driver\n"
    "\t-d [Optional: <driver>]\t\t\tDump kernel symbols or symbols for a specified driver\t\n"
    "\n"
  );
}

/**
 * @brief Prints the parsed module information.
 */

void print_module_information(const kmodule_t *module) {
  printf(
    "'%s' Module Information:\n"
    "\tSize: %lx\n"
    "\tInstances: %d\n"
    "\tDependencies: %s\n"
    "\tState: %s\n"
    "\tKernel Memory Offset: 0x%lx\n\n",
    module->kmodule,
    module->size,
    module->instances,
    module->dependencies,
    module->state,
    module->offset
  );
}

/**
 * @brief Parses the information in the given entry.
 * @param information The struct where the parsed information will be stored in.
 * @param string The string.
 * @returns A struct containing the parsed module information, NULL if otherwise.
 */

kmodule_t *parse_loaded_module_data(kmodule_t *information, const uint8_t *string) {
  if (sscanf(string, "%s %lx %d %s %s %lx", information->kmodule, &information->size, &information->instances, information->dependencies, information->state, &information->offset) == 0)
    return NULL;
  return information;
}

/**
 * @brief Parses the information in the given entry.
 * @param information The struct where the parsed information will be stored in.
 * @param string The string.
 * @returns A struct containing the parsed symbol information, NULL if otherwise.
 */

syscall_t *parse_kernel_symbol_information(syscall_t *information, const uint8_t *string) {
  if (sscanf(string, "%lx %s %s %s", &information->addr, information->symbol_type, information->symbol, information->kmodule) == 0)
    if (sscanf(string, "%lx %s %s", &information->addr, information->symbol_type, information->symbol) == 0)
      return NULL;
  return information;
}

/**
 * @brief Resolves information about a given kernel symbol.
 * @param kernel_symbol The kernel symbol that will be resolved.
 * @returns A struct containing the parsed symbol information, NULL if otherwise.
 */

syscall_t *resolve_kernel_symbol(const uint8_t *kernel_symbol) {
  FILE *file;
  uint8_t buffer[BUFSIZ] = {0};

  syscall_t *temp = NULL, *information = (syscall_t *)malloc(sizeof(syscall_t));
  if (!information || !(file = fopen("/proc/kallsyms", "r")))
    return NULL;

  while (fgets(buffer, sizeof(buffer), file))
    if (strstr(buffer, kernel_symbol))
      temp = parse_kernel_symbol_information(information, buffer);

  fclose(file);
  free(information);

  return temp;
}

/**
 * @brief Iterates over the kernel symbols.
 * @param driver The name of the driver that will be filtered.
 * @returns True if the file could be accessed, false if otherwise.
 */

bool iterate_kernel_symbols(const uint8_t *driver) {
  uint8_t buffer[BUFSIZ] = {0};
  syscall_t *temp = NULL, *information = (syscall_t *)malloc(sizeof(syscall_t));
  
  FILE *file = fopen("/proc/kallsyms", "r");
  if (!file || !information)
    return false;

  while (fgets(buffer, sizeof(buffer), file)) {
    if (!(temp = parse_kernel_symbol_information(information, buffer)))
      continue;
    
    if (!driver) {
      kutil_log("Symbol: %s | Symbol Type: %s | Address: 0x%lx\n", temp->symbol, temp->symbol_type, temp->addr);
      continue;
    }

    if (strstr(buffer, driver))
      kutil_log("Symbol: %s | Symbol Type: %s | Address: 0x%lx\n", temp->symbol, temp->symbol_type, temp->addr);
  }

  fclose(file);
  free(information);

  return true;
}

/**
 * @brief Fetches data about the kernel module.
 * @param module_name The name of the kernel module.
 * @returns True if the file descriptor could be opened, false if otherwise.
 */

bool fetch_module_data(const uint8_t *module_name) {
  uint8_t buffer[BUFSIZ] = {0};
  
  FILE *file = fopen("/proc/modules", "r");
  kmodule_t *temp = NULL, *information = (kmodule_t *)malloc(sizeof(kmodule_t));
  
  if (!file || !information)
    return false;
  
  while (fgets(buffer, sizeof(buffer), file))
    if ((temp = parse_loaded_module_data(information, buffer)))
      if (strncmp(temp->kmodule, module_name, strlen(temp->kmodule)) == 0)
        print_module_information(temp);

  fclose(file);
  free(information);

  return true;
}

/**
 * @brief Removes a kernel module.
 * @param module_name The name of the kernel module that will be removed.
 * @returns True if the module was able to be removed, false if otherwise.
 */

bool remove_kernel_module(const uint8_t *module_name) {
  if (syscall(__NR_delete_module, module_name, O_NONBLOCK) != 0)
    return false;
  return true;
}

/**
 * @brief Inserts a kernel module.
 * @param params The parameters.
 * @param module_name The name of the kernel module that will be inserted.
 * @returns True if the module was able to be inserted, false if otherwise.
 */

bool insert_kernel_module(const uint8_t *params, const uint8_t *module_path) {
  int32_t file;
  void *module;
  struct stat st_stat;

  if ((file = open(module_path, O_RDONLY)) == -1)
    return false;

  /**
   * Getting the size of the file and allocating enough memory for us to read from it.
   */

  if (fstat(file, &st_stat) == -1 || !(module = malloc(st_stat.st_size)))
    return false;
  
  /**
   * Reading the data from the file.
   */

  if (read(file, module, st_stat.st_size) == -1)
    return false;

  /**
   * Attempting to insert the driver into kernel memory, if we fail, then we try to use finit_module as a last resort.
   */

  if (!module_path) {
    if (syscall(__NR_init_module, module, st_stat.st_size, "") != 0) {
      free(module);
      return invoke_finite_module(params, module_path);
    }
  }

  if (syscall(__NR_init_module, module, st_stat.st_size, params) != 0) {
    free(module);
    return invoke_finite_module(params, module_path);
  }

  /**
   * Closing our file descriptors and freeing our memory.
   */

  close(file);
  free(module);

  return true;
}

/**
 * @brief Inserts a kernel module via invoking the finite_module system call.
 * @param params The parameters.
 * @param module_path The name of the kernel module that will be inserted.
 * @returns True if the module was able to be inserted, false if otherwise.
 */

bool invoke_finite_module(const uint8_t *params, const uint8_t *module_path) {
  int32_t file = open(module_path, O_RDONLY);
  if (file == -1)
    return false;

  if (!module_path)
    if (syscall(__NR_finit_module, file, "", 0) != 0)
      return false;

  if (syscall(__NR_finit_module, file, module_path, 0) != 0)
    return false;

  close(file);
  return true;
}

/**
 * @brief Appends a node to the linked list.
 * @param head The head of linked list.
 * @param index The index.
 * @param token The token.
 */

void append_token(token_t **head, const int32_t index, const uint8_t *token) {
  token_t *prev = *head, *node_token = (token_t *)malloc(sizeof(token_t));
  node_token->next = NULL, node_token->index = index, node_token->token = (uint8_t *)token;
  
  if (!(*head)) {
    *head = node_token;
    return;
  }

  while (prev->next)
    prev = prev->next;

  prev->next = node_token;
}

/**
 * @brief Deletes a node from the linked list.
 * @param head The head of linked list.
 * @param index The index.
 */

void delete_token(token_t **head, const int32_t index) {
  token_t *temp = *head, *previous = NULL;

  /**
   * Checks the index, and then deletes the node by freeing the allocated memory.
   */

  if (temp && temp->index == index) {
    *head = (struct _node *)temp->next;
    free(temp);
    return;
  }

  while (temp && temp->index != index)
    previous = temp, temp = (struct _node *)temp->next;

  if (!temp)
    return;

  previous->next = temp->next;
  free(temp);
}

/**
 * @brief Prints the parsed and formatted version of the given kernel log.
 * @param head The head of the linked list.
 */

void print_formatted_messages(token_t *head) {
  kutil_log("%s: %s\n", head->token, head->next->token);
  
  for (int32_t i = 0; i < 2; i++)
    delete_token(&head, i);
}

/**
 * @brief Returns a parsed and formatted version of the given kernel log.
 * @param log The log.
 * @returns The head of the linked list.
 */

token_t *return_parsed_messages(const uint8_t *log) {
  token_t *head = NULL;
  uint8_t *temp = NULL, *token = strtok_r((char *)log, ";", (char **)&temp);

  append_token(&head, 0, (token = strtok_r(NULL, ":", (char **)&temp)));
  append_token(&head, 1, (token = strtok_r(NULL, "", (char **)&temp)));

  return head;
}

/**
 * @brief Reads the data stored in the kernel ring buffer.
 * @returns True if the file could be accessed, false if otherwise.
 */

bool read_kernel_logs(void) {
  size_t bytes_read = 0;

  uint8_t buffer[BUFSIZ] = {0};
  int32_t fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);

  if (fd == -1)
    return false;

  while (1) {
    bytes_read = read(fd, buffer, sizeof(buffer));

    if (bytes_read == 0 || bytes_read == -1)
      break;

    print_formatted_messages(return_parsed_messages(buffer));
    memset(buffer, 0, sizeof(buffer));
  }

  close(fd);
  return true;
}

/**
 * @brief Handles the given command-line arguments.
 * @param argc The argument count.
 * @param argv The argument vector.
 * @returns True if the arguments were handled, false if otherwise.
 */

bool handle_arguments(const int32_t argc, const int8_t **argv) {
  int32_t opt;
  uint8_t *token = NULL;
  
  while ((opt = getopt(argc, (char **)argv, ":hirsld")) != -1) {
    switch (opt) {
      case 'h': print_help(); return true;
      case 'i': if (argv[2]) return insert_kernel_module(NULL, argv[2]); if (argv[2] && argv[3]) return insert_kernel_module(argv[3], argv[2]);
      case 'r': if (argv[2]) return remove_kernel_module(strtok_r((uint8_t *)argv[2], ".", (char **)&token));
      case 's': if (argv[2]) return fetch_module_data(strtok_r((uint8_t *)argv[2], ".", (char **)&token));
      case 'l': return read_kernel_logs();
      case 'd': if (argv[2]) return iterate_kernel_symbols(strtok_r((uint8_t *)argv[2], ".", (char **)&token)); return iterate_kernel_symbols(NULL);
      default: return false;
    }
  }
  
  return false;
}

/**
 * @brief Entry point for the 'kutil' program.
 * @param argc The argument count.
 * @param argv The argument vector.
 * @returns EXIT_SUCCESS if the program was able to properly execute, EXIT_FAILURE if otherwise.
 */

int32_t main(int32_t argc, int8_t **argv) {
  fprintf(stderr, "Usage: %s [-h] [-l, -i, -r, -s, -d] <driver>\n\n", argv[0]);

  if (argc < 2 || getuid() != 0)
    return EXIT_FAILURE;

  if (!handle_arguments(argc, (const int8_t **)argv))
    return EXIT_FAILURE;

  return EXIT_SUCCESS;
}