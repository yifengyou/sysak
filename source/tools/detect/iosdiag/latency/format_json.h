#ifndef _FORMAT_JSON_H
#define _FORMAT_JSON_H

#define JSON_BUFFER_SIZE	4096
void set_check_time_date(void);
void summary_convert_to_json(void *dest, void *src);
void delay_convert_to_json(void *dest, void *src);
void point_convert_to_json(void *dest, void *src);
#endif

