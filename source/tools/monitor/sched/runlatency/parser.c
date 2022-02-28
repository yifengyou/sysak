#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>
#include "parser.h"
#include "cJSON.h"

enum IRQOFF{
	HARD_IRQ,
	SOFT_IRQ,
};

static char* accept(char* s, char c)
{
	while (*s != '\0'){
		if (*s == c) {
			break;
		}
		s ++;
	}
	
	if (*s == '\0') {
		return s;
	}
	return s + 1;
}

static char* accepts(char* s, char c1, char c2)
{
	while (*s != '\0'){
		if (*s == c1||*s == c2) {
			break;
		}
		s ++;
	}
	
	if (*s == '\0') {
		return s;
	}
	return s + 1;
}

bool isdigits(char *s) 
{
	while (*s != '\0') {
		if (isdigit(*s) == 0) {
			return false;
		}
		s ++;
	}
	return true;
}

static char* copy_name(char *beg, int size)
{
	char *s = malloc(size);
	if (s == NULL) {
		fprintf(stderr,"can't malloc memory!");
		exit(1);
	}
	memcpy(s, beg, size - 1);
	s[size - 1] = '\0';
	return s;
}

static char* parser_args(char* beg, cJSON *parent)
{
	char *cur, *s;
	char *title, *value;
	int size;
	
	s = beg;
	while (1) {
		cur = accept(s, ':');
		size = cur - s;
		title = copy_name(s, size);
		
		s = cur;
		cur = accepts(s, '\t', '\n');
		size = cur - s;
		value = copy_name(s, size);
		
		if (isdigits(value)) {
			int base = 10;
			char* endPtr;
			
			cJSON_AddNumberToObject(parent, title, strtoull(value, &endPtr, base));
		}
		else {
			cJSON_AddStringToObject(parent, title, value);
		}
		free(title);
		free(value);
		if (s[size - 1] == '\n') {
			break;
		}
		s = cur;
	}
	return cur;
}

/*
	trace_irqoff_latency: 10ms

 hardirq:
     cpu:1	COMMAND:insmod	PID:1951	LATENCY:202ms	STAMP:5160856147
     do_one_initcall+0xb8/0x230
     load_module+0x1318/0x1b40
     SYSC_finit_module+0x9e/0xd0
     SyS_finit_module+0xe/0x10
     system_call_fastpath+0x16/0x1b

     cpu:1	COMMAND:insmod	PID:1954	LATENCY:203ms	STAMP:5162868155
     do_one_initcall+0xb8/0x230
     load_module+0x1318/0x1b40
     SYSC_finit_module+0x9e/0xd0
     SyS_finit_module+0xe/0x10
     system_call_fastpath+0x16/0x1b
 softirq:
 
trace_irqoff_latency: 10ms

 hardirq:
 softirq:
*/
static char* head_args(char* beg, cJSON *parent)
{
	char *s = beg;
	
	while (*s == ' ') s ++;
	beg = s;
	return parser_args(beg, parent);
}

static char* stack_get(char* beg, cJSON *parent)
{
	char *s, *cur;
	char *stack;
	int size;
	cJSON *arr;
	
	arr = cJSON_CreateArray();
	s = beg;
	while (*s != '\n') {
		while (*s == ' ') s ++;
		cur = accept(s, '\n');
		
		size = cur - s;
		stack = copy_name(s, size);
		cJSON_AddItemToArray(arr, cJSON_CreateString(stack));
		free(stack);
		
		s = cur;
	}
	cJSON_AddItemToObject(parent, "stack", arr);
	return s + 1;   // enter + 1
}

static char* body_irqoff(char* beg, enum IRQOFF stat, FILE *file)
{
	char *s;
	cJSON *root;
	char *out;
	
	root = cJSON_CreateObject();
	
	if (stat == HARD_IRQ){
//		printf("hard\n");
		cJSON_AddStringToObject(root, "mode", "hard");
	}
	else {
//		printf("soft\n");
		cJSON_AddStringToObject(root, "mode", "soft");
	}
	
	s = head_args(beg, root);
	s = stack_get(s, root);
	
	out = cJSON_Print(root);
	if (!file)
		printf("%s\n", out);
	else
		fprintf(file, "%s\n", out);
	free(out);
	cJSON_Delete(root);
	return s;
}

int parser_irqoff(char *stream, int size, FILE *file)
{
	char *sBeg, *sCursor;
	enum IRQOFF stat = HARD_IRQ;
	
	sCursor = accept(stream, '\n');
	sCursor = accept(sCursor, '\n');
	sCursor = accept(sCursor, '\n');
	
	sBeg = sCursor;
	while (sBeg[1] != 's') {
		sBeg = body_irqoff(sBeg, stat, file);
	}
	
	stat = SOFT_IRQ;
	sBeg = accept(sBeg, '\n');
	while (sBeg[0] != '\0') {
		sBeg = body_irqoff(sBeg, stat, file);
	}
	return 0;
}

static char* body_nosch(char* beg, FILE *file)
{
	char *s;
	cJSON *root;
	char *out;
	
	root = cJSON_CreateObject();
	
	cJSON_AddStringToObject(root, "mode", "nosch");
	s = head_args(beg, root);
	s = stack_get(s, root);
	
	out = cJSON_Print(root);
	if (!file)
		printf("%s\n", out);
	else
		fprintf(file, "%s\n", out);
	free(out);
	cJSON_Delete(root);
	return s;
}

int parser_nosch(char *stream, int size, FILE *file)
{
	char *sBeg;
	
	sBeg = stream;
	while (sBeg[0] != '\0') {
		sBeg = body_nosch(sBeg, file);
	}
	return 0;
}

static char* body_runq(char* beg, FILE *file)
{
	char *s = beg;
	cJSON *root, *arr;
	char *out;
	
	root = cJSON_CreateObject();
	cJSON_AddStringToObject(root, "mode", "runq");
	s = head_args(s, root);

	out = cJSON_Print(root);
	if (!file)
		printf("%s\n", out);
	else
		fprintf(file, "%s\n", out);
	free(out);
	cJSON_Delete(root);
	return s + 1;
}

int parser_runq(char *stream, int size, FILE *file)
{
	char *sBeg;
	
	sBeg = stream;
	while (sBeg[0] != '\0') {
		sBeg = body_runq(sBeg, file);
	}
	return 0;
}
