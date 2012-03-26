
#ifndef _RUNSCRIPT_H_
#define _RUNSCRIPT_H_

struct rs_data;

struct rs_data *get_RunScript();
const char *get_RunScript_command(struct rs_data *ptr);
void add_RunScript(unsigned int start_time, unsigned int end_time, const char *cmd);

#endif

