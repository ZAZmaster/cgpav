#ifndef __UTIL_H
#define __UTIL_H

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>


#include "cfg.h"
#include "email.h"

/* settings structure */
extern struct settings *sett;


/* read line from socket */
int readline(int timeout, int fd, char *bufptr, size_t len);

/* reading from the socket with timeout */
int timeout_read(int timeout, int fd, char *buf, int len);

/* this procedure removes the given pattern from the text */
void clear_string(char *pat, char **text);

/* this procedure replaces the given char to another */
void tr_string(char **text, char from, char to);

/* replace the pattern in a string */
int string_replace(char *pattern, char *replace, char **str);

/* copy a file */
int copy_file(char *from_file, char *to_file);

/* add a new element to the end of the char vector */
int push_back_vector(char_vector *vec, char *new_val);

/* free contents of the vector */
void free_vector(char_vector *vec);

/* split string and add elements to the char vector */
int split_string(char *pattern, char *str, char_vector *vec);

/* made a string from the char vector inserting glues */
char *join_vector(char *glue, char_vector *vec);

/* add a new element to the end of the ip vector */
int push_back_ip_vector(ip_vector *vec, unsigned long new_from, 
		     unsigned long new_to);

/* free contents of the ip vector */
void free_ip_vector(ip_vector *vec);

/* add a new element to the end of nameval vector */
int push_back_nameval_vector(nameval_vector *vec, char *new_name, 
			     char *new_val);

/* free contents of the vector */
void free_nameval_vector(nameval_vector *vec);

/* split string with networks and add elements to the ip vector */
int split_ip_string(char *pattern, char *str, ip_vector *vec);

/* split string with hash elements: key1 => val1, key2 => val2 */
int split_hash_string(char *pattern, char *str, nameval_vector *vec);

/* convert the given ip address in native byte order to a printable string */
char *my_ntoa(unsigned long ip);


#endif
