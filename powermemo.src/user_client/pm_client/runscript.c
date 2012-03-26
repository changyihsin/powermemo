
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RUN_SCRIPT_LEN	500

struct rs_data {
	char rs_cmd[RUN_SCRIPT_LEN];
	struct rs_data *next_ptr;
};

static struct rs_data *rs_head = NULL;

void add_RunScript(unsigned int start_time, unsigned int end_time, const char *cmd)
{
	struct rs_data *ptr = malloc(sizeof(struct rs_data));
	sprintf(ptr->rs_cmd, "sh rs.sh \"%s\" %d %d &", cmd, start_time, end_time);
	
	printf("rs command: [%s]\n", ptr->rs_cmd);

	struct rs_data *tmp = rs_head;
	rs_head = ptr;
	ptr->next_ptr = tmp;
}

struct rs_data *get_RunScript()
{
	struct rs_data *ptr = rs_head;

	if (rs_head != NULL) { 
		rs_head = rs_head->next_ptr;
	}

	return ptr;
}
const char *get_RunScript_command(struct rs_data* ptr)
{
	return ptr->rs_cmd;
}


