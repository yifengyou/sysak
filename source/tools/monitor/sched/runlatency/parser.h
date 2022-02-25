#ifndef _PARSER_H
#define _PARSER_H
int parser_irqoff(char *stream, int size, FILE *file);
int parser_nosch(char *stream, int size, FILE *file);
int parser_runq(char *stream, int size, FILE *file);
int parse_dump(char *file);
#endif
