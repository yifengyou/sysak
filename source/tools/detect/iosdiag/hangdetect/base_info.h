#ifndef __BASE_INFO_H
#define __BASE_INFO_H

struct base_disk_info {
	int major;
	int minor;
	char diskname[128];
};

struct base_mnt_info {
	char mnt_dir[128];
	char diskname[128];
};

struct base_info {
	char *check_time_date;
	char *comm;
	char *file;
	struct base_disk_info *bdi;
	struct base_mnt_info *bni;
	int pid;
};

int set_current_bdi_idx(int idx);
int get_current_bdi_idx(void);
int get_bdi_cnt(void);
char *get_bdi_mnt_dir(char *diskname);
struct base_info *get_base_info_ptr(void);
struct base_disk_info *get_current_bdi(void);
int base_info_init(char *diskname);
void base_info_exit(void);

#define get_bdi(name)			get_current_bdi()->##name
#define get_base_info(name)		get_base_info_ptr()->##name
#define set_base_info(name, value)	(get_base_info_ptr()->##name = value)

#define get_bdi_major()				get_current_bdi()->major
#define get_bdi_minor()				get_current_bdi()->minor
#define get_bdi_diskname()			get_current_bdi()->diskname
#define get_base_info_pid()			get_base_info_ptr()->pid
#define get_base_info_comm()			get_base_info_ptr()->comm
#define get_base_info_file()			get_base_info_ptr()->file
#define get_base_info_check_time_date()		get_base_info_ptr()->check_time_date
#define set_base_info_pid(v)			(get_base_info_ptr()->pid = v)
#define set_base_info_comm(v)			(get_base_info_ptr()->comm = v)
#define set_base_info_file(v)			(get_base_info_ptr()->file = v)
#define set_base_info_check_time_date(v)	(get_base_info_ptr()->check_time_date = v)
#endif

