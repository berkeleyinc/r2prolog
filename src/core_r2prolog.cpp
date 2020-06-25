#include "core_r2prolog.h"

#include <errno.h>
#include <r_cmd.h>
#include <r_core.h>
#include <r_io.h>
#include <r_lib.h>
#include <r_main.h>
#include <r_userconf.h>
#include <stdio.h>
#include <stdlib.h>

#include "prolog.h"

#define CMD_PREFIX "ppl"
#define CFG_PREFIX "r2prolog"

extern RCorePlugin r_core_plugin_prolog; // forward declaration

static char *__system(RCore *io, const char *command) {
  printf("%s command: %s\n", __func__, command);
  // io->cb_printf()
  return NULL;
}

static void _cmd(RCore *core, const char *input) { r2_cmd(core, input); }

int main(int argc, const char **argv) {
  auto core = r_core_new();
  r_core_loadlibs(core, R_CORE_LOADLIBS_ALL, NULL);
  RCoreFile *fd = r_core_file_open(core, "self://", R_PERM_R, 0);
  //RCoreFile *fd = r_core_file_open(core, "file:///home/yuri/tt/xm/horcruxes", R_PERM_RX, 0);
  
  r_core_prompt_loop(core);
}

static int r2prolog_init(void *user, const char *input) {
  return r2_init((RCore *)user, input);
}
static int r2prolog_fini(void *user, const char *input) {
  return r2_fini((RCore *)user, input);
}

static int r2prolog_cmd(void *user, const char *input) {
  RCore *core = (RCore *)user;
  if (!strncmp(input, CMD_PREFIX, strlen(CMD_PREFIX))) {
    _cmd(core, input + 3);
    return true;
  }
  return false;
}

RCorePlugin r_core_plugin_prolog = {
    /* .name = */ "r2prolog",
    /* .desc = */ "Prolog integration",
    /* .license = */ "LGPL",
    /* .author = */ "advibm",
    /* .version = */ nullptr,
    /*.call = */ r2prolog_cmd,
    /*.init = */ r2prolog_init,
    /*.fini = */ r2prolog_fini};

#ifndef CORELIB
RLibStruct radare_plugin = {.type = R_LIB_TYPE_CORE,
                            .data = &r_core_plugin_prolog,
                            .version = R2_VERSION};
#endif
