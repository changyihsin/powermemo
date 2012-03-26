#ifndef	__POWER__H__
#define	__POWER__H__

#include <linux/ioctl.h>

struct power_cmd {
	char filename[32];
	char function[32];
	int address;
	int start_address;
	int end_address;
	int start_line;
	int end_line;
	int line;
	int action;
	char image[32];
};

#define IOC_MAGIC 'P'


#define REGISTER_KPROBE_CMD_SHOW		_IOW(IOC_MAGIC, 0x6B01, struct power_cmd)
#define REGISTER_KPROBE_CMD				_IOW(IOC_MAGIC, 0x6B02, struct power_cmd)
#define UNREGISTER_KPROBE_CMD			_IOW(IOC_MAGIC, 0x6B03, struct power_cmd)
#define REGISTER_UPROBE_CMD_SHOW		_IOW(IOC_MAGIC, 0x6B04, struct power_cmd)
#define REGISTER_UPROBE_CMD				_IOW(IOC_MAGIC, 0x6B05, struct power_cmd)
#define UNREGISTER_UPROBE_CMD			_IOW(IOC_MAGIC, 0x6B06, struct power_cmd)

#define REGISTER_DUAL_KPROBE_CMD        _IOW(IOC_MAGIC, 0x6B07, struct power_cmd)
#define UNREGISTER_DUAL_KPROBE_CMD      _IOW(IOC_MAGIC, 0x6B08, struct power_cmd)
#define REGISTER_DUAL_UPROBE_CMD        _IOW(IOC_MAGIC, 0x6B09, struct power_cmd)
#define UNREGISTER_DUAL_UPROBE_CMD      _IOW(IOC_MAGIC, 0x6B0A, struct power_cmd)

#define REGISTER_SCHEDULE_CMD			_IOW(IOC_MAGIC, 0x6B10, struct power_cmd)
#define UNREGISTER_SCHEDULE_CMD			_IOW(IOC_MAGIC, 0x6B11, struct power_cmd)

#define REGISTER_FUNCTION_KPROBE_CMD	_IOW(IOC_MAGIC, 0x6B12, struct power_cmd)	
#define UNREGISTER_FUNCTION_KPROBE_CMD	_IOW(IOC_MAGIC, 0x6B13, struct power_cmd)	
#define REGISTER_FUNCTION_UPROBE_CMD	_IOW(IOC_MAGIC, 0x6B14, struct power_cmd)	
#define UNREGISTER_FUNCTION_UPROBE_CMD	_IOW(IOC_MAGIC, 0x6B15, struct power_cmd)	



#define GET_MEASURE_RESULT_CMD			_IOW(IOC_MAGIC, 0x6B0B, struct power_cmd)

#define SINGLE_PROBE	1
#define DUAL_PROBE 		2
#define RET_PROBE		3

#endif
