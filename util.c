/* $Id: util.c, v 1.5 2010/07/01 12:00:00 farit Exp $ */

#include "util.h"

/* first we allocate memory only for 1 element */
#define VECTOR_INIT 1
/* we will allocate memory for the vector 2 times more than needed */
#define VECTOR_GROW 2


/* read line from the socket */
int readline(int timeout, int fd, char *bufptr, size_t len)
{
    char *bufx = NULL;
    static char *bp = NULL;
    static int cnt = 0;
    static char b[100];
    char c;

    bufx = bufptr;
    while (--len > 0) {
	if (--cnt <= 0) {
	    cnt = timeout_read(timeout, fd, b, sizeof(b));
	    if (cnt < 0) {
		if (errno == EINTR) {
		    len++;
		    continue;
		}
		return -1;
	    }
	    if (cnt == 0)
		return 0;
	    bp = b;
	}
	c = *bp++;
	*bufptr++ = c;
	if (c == '\n') {
	    *bufptr = '\0';
	    return (bufptr - bufx);
	}
    }
    return -1;
}


/* read from the socket with timeout */
int timeout_read(int timeout, int fd, char *buf, int len)
{
    fd_set rfds;
    struct timeval tv;

    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    if (select(fd + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv) == -1)
	return -1;

    if (FD_ISSET(fd, &rfds))
	return read(fd, buf, len);

    return -1;
}

/* this procedure removes the given pattern from the text */
void clear_string(char *pat, char **text)
{
    int p_end;
    int pat_len;
    char *p;
    
    if (!pat || !text)
	return;
    
    pat_len = strlen(pat);
    p = *text;

    for (; *p != '\0'; p++) {
	if (strncmp(pat, p, pat_len) == 0) {
	    p_end = strlen(p) - pat_len;
	    /* clear the pattern by moving next chars to the left */
	    memmove(p, p + pat_len, p_end);
	    p[p_end] = '\0';
	    /* here we moved chars */
	    p--;
	}
    }
    
    return;
}

/* this procedure replaces the given char to another */
void tr_string(char **text, char from, char to)
{
    char *p = *text;

    for (; *p != '\0'; p++) {
	if (*p == from) 
	    *p = to;
    }
    
    return;
}

/* replace the pattern in a string */
int string_replace(char *pattern, char *replace, char **str)
{
    char *ptr = NULL;
    char *ret = NULL;
    char *tmp = NULL;
    int pattern_len, replace_len, str_len, ret_len;
    int diff = 0;
    int counter = 0;
    
    if (!pattern || !str)
	return -1;

    pattern_len = strlen(pattern);
    replace_len = strlen(replace);
    diff = replace_len - pattern_len;

    /* copy of the original message */        	
    tmp = strdup(*str);
    if (!tmp)
	return -1;
    
    for (ptr = tmp, counter = 0; *ptr != '\0'; ptr++, counter++) {
	if (strncasecmp(pattern, ptr, pattern_len) == 0) {	    
	    str_len = strlen(*str);
	    
	    /* if replace < or > pattern then resize */
	    if (diff >= 0)
		ret_len = str_len + diff;
	    else
		ret_len = str_len - diff;	

	    /* return buffer */
	    ret = (char *)malloc(ret_len + 1);
	    if (!ret) {
		free(tmp);
		return -1;
	    }	
	    
	    /* part before the pattern */
	    strncpy(ret, *str, counter);
	    ret[counter] = '\0';
	    /* pattern itself */
	    strncat(ret, replace, replace_len);
	    /* part after the pattern */
	    strncat(ret, ptr + pattern_len, tmp - (ptr + pattern_len));	    
	    ret[ret_len] = '\0';
	    		
	    /* resize string to have enough place for replaced */
	    *str = (char *)realloc(*str, ret_len + 1);
	    if (!*str) {
		free(ret);
		free(tmp);
		return -1;
	    }			
	    
	    strcpy(*str, ret);
	    if (ret)
		free(ret);
	    
	    ptr += pattern_len;
	    counter += replace_len;
	}
    }
    
    if (tmp)
	free(tmp);
    
    return 0;
}


/* copy a file */
int copy_file(char *from_file, char *to_file)
{
    FILE *in, *out;
    int len = 0;
    char buffer[1024];
    int mask = 0;

    /* there must be absolute paths which are hardly less than 2 chars long */
    if (!from_file || !to_file || (strlen(from_file) <= 2) 
	|| (strlen(to_file) <= 2))
	return -1;
    
    if ((in = fopen(from_file, "r")) == NULL)
	return -1;
    
    if ((out = fopen(to_file, "w")) == NULL)
	return -1;	

    while ((len = fread(buffer, 1, sizeof(buffer), in)) > 0) {
	fwrite(buffer, 1, len, out);
    }
    
    fclose(in);
    fclose(out);

    /* change file permission */
    mask = umask(0);
    umask(mask);
    chmod(to_file, 0660 & ~mask);

    
    return 0;
}


/* add a new element to the end of the char vector */
int push_back_vector(char_vector *vec, char *new_val)
{
    char **tmp = NULL;
    int i = 0;

    if (!vec || !new_val)
        return -1;
        
    /* first value of the vector */
    if (!vec->val || (vec->size <= 0)) {
        vec->val = (char **)malloc(VECTOR_INIT * sizeof(char *));
        if (!vec->val)
            return -1;
    
        vec->max = VECTOR_INIT;
        vec->size = 0;    
    }
    /* expand if memory hasn't been allocated for those number of elements */
    else if (vec->size >= vec->max) {        
        /* we don't want to lose anything in case of an error, thus tmp */
        tmp = (char **)realloc(vec->val, (VECTOR_GROW * vec->max)
                                         * sizeof(char *));
        if (!tmp)
            return -1;
            
        vec->val = tmp;
        /* we reserve some space in order not to allocate memory often */
        vec->max *= VECTOR_GROW;    
    }

    /* we don't want double values in the vector */
    if (vec->size > 0) {
	for (i = 0; i < vec->size; i++) {
	    if (vec->val[i] && (strcasecmp(vec->val[i], new_val) == 0))
		return 0;	
	}
    }
    
    /* now we can actually add a new element */
    vec->val[vec->size] = (char *)malloc(strlen(new_val) + 1);
    if (!vec->val[vec->size])
	return -1;

    strcpy(vec->val[vec->size], new_val);
    vec->size++;
    
    return 0;
}

/* free contents of the vector */
void free_vector(char_vector *vec)
{
    int i;
    
    if (!vec)
        return;
    
    for (i = 0; i < vec->size; i++) {
        if (vec->val[i] != NULL)
            free(vec->val[i]);
    }                
    
    vec->size = 0;
    if (vec->val)
	free(vec->val);
    free(vec);
    vec = NULL;
}

/* remove an element from the vector by index */
/* 
int remove_element_vector(char_vector *vec, int index)
{
    if (!vec || !index)
        return -1;        
    if (index >= vec->size)
        return 0;

    memmove(vec->val + index, vec->val + index + 1,
            (vec->size - (index + 1)) * sizeof(char *));
    vec->size--;
            
    return 1;
}
*/

/* split string and add elements to the vector */
int split_string(char *pattern, char *str, char_vector *vec)
{
    char *ptr = NULL;
    char *tmp = NULL;
    
    if (!pattern || !str || !vec || (strlen(str) <= 2))
	return 0;

    /* behave well, use a copy */
    tmp = strdup(str);
    if (!tmp)
	return -1;

    ptr = strtok(tmp, pattern);
    if (!ptr) {
	free(tmp);
	return -1;
    }	
    push_back_vector(vec, ptr);		

    while (ptr) {
	ptr = strtok(NULL, pattern);		
	if (ptr)
	    push_back_vector(vec, ptr);
    }
    
    free(tmp);
    
    return 0;
}

/* made a string from the vector inserting glues */
char *join_vector(char *glue, char_vector *vec)
{
    char *tmp = NULL;
    int i = 0;
    int len = 0;

    if (!glue || !vec || (vec->size <= 0))
	return NULL;
	
    /* count the total length of all vec elements */
    for (i = 0; i < vec->size; i++) {
        if (vec->val[i] != NULL)
            len += strlen(vec->val[i]);
    }                
    /* count the total length of all glues */
    len += strlen(glue) * (vec->size - 1);	

    tmp = (char *)malloc(len + 1);
    if (!tmp)
	return NULL;

    for (i = 0; i < vec->size; i++) {
        if (vec->val[i] != NULL) {
	    if (i == 0)
		strcpy(tmp, vec->val[i]);
	    else	
        	strcat(tmp, vec->val[i]);
	    /* no glue after the last element */    
	    if (i < (vec->size - 1))
		strcat(tmp, glue);    
	}	
    }          
          
    return tmp;	
}

/* add a new element to the end of ip vector */
int push_back_ip_vector(ip_vector *vec, unsigned long new_from, 
		     unsigned long new_to)
{
    ip_range **tmp = NULL;
    int i = 0;

    if (!vec || !new_from || !new_to)
        return -1;
        
    /* first value of the vector */
    if (!vec->val || (vec->size <= 0)) {
        vec->val = (ip_range **)malloc(VECTOR_INIT * sizeof(ip_range *));
        if (!vec->val)
            return -1;
    
        vec->max = VECTOR_INIT;
        vec->size = 0;    
    }
    /* expand if memory hasn't been allocated for those number of elements */
    else if (vec->size >= vec->max) {        
        /* we don't want to lose anything in case of an error, thus tmp */
        tmp = (ip_range **)realloc(vec->val, (VECTOR_GROW * vec->max)
                                         * sizeof(ip_range *));
        if (!tmp)
            return -1;
            
        vec->val = tmp;
        /* we reserve some space in order to prevent allocating memory often */
        vec->max *= VECTOR_GROW;    
    }

    /* we don't want double values in the vector */
    if (vec->size > 0) {
	for (i = 0; i < vec->size; i++) {
	    if (vec->val[i] 
	        && vec->val[i]->from && (vec->val[i]->from == new_from) 
	        && vec->val[i]->to && (vec->val[i]->to == new_to))
		return 0;	
	}
    }
    
    /* now we can actually add a new element */
    vec->val[vec->size] = (ip_range *)malloc(sizeof(ip_range));
    if (!vec->val[vec->size])
	return -1;

    vec->val[vec->size]->from = new_from;
    vec->val[vec->size]->to = new_to;

    vec->size++;
    
    return 0;
}

/* free contents of the vector */
void free_ip_vector(ip_vector *vec)
{
    int i;
    
    if (!vec)
        return;
    
    for (i = 0; i < vec->size; i++) {
        if (vec->val[i] != NULL)
            free(vec->val[i]);
    }                
    
    vec->size = 0;
    if (vec->val)
	free(vec->val);
    free(vec);
    vec = NULL;
}

/* compute the ip range, parsing mask etc */
static int parse_network(char *str, ip_vector *vec)
{
    char *tmp = NULL;
    char *ptr = NULL;
    unsigned long from_ip = 0L;
    unsigned long to_ip = 0L;
    in_addr_t ip_address, ip_mask;
    unsigned long mask, network, broadcast;
    int mask_bits;
    int i;
    
    if (!str || !vec)
	return -1;
	
    /* make a copy */	
    tmp = strdup(str);
    if (!tmp)
	return -1;
    
    /* ip-ip range */
    if ((ptr = strchr(tmp, '-')) && *ptr) {
	*ptr = 0;
	ptr++;	

	/* convert the address into long int that's easy to compare */
	ip_address = inet_addr(tmp);
	if (ip_address != -1)
	    from_ip = ntohl(ip_address);
	else {
	    syslog(LOG_ERR, "%s is not a valid IP address", tmp);
	    if (tmp)
		free(tmp);
	    return -1;
    	}
	
	ip_address = inet_addr(ptr);
	if (ip_address != -1)
	    to_ip = ntohl(ip_address);
	/* error */    
	else {
	    syslog(LOG_ERR, "%s is not a valid IP address", ptr);	
	    if (tmp)
		free(tmp);
	    to_ip = from_ip;	
	    return -1;
	}    
    }
    /* ip/mask range */
    else if ((ptr = strchr(tmp, '/')) && *ptr) {
	*ptr = 0;
	ptr++;

	/* convert the address into long int that's easy to compare */
	ip_address = inet_addr(tmp);
	if (ip_address != -1)
	    from_ip = ntohl(ip_address);
	else {
	    syslog(LOG_ERR, "%s is not a valid IP address", tmp);
	    if (tmp)
		free(tmp);
	    return -1;
    	}
	
	/* dotted mask: 255.255.255.0 */
	if (strchr(ptr, '.')) {
	    ip_mask = inet_addr(ptr);
	    if (ip_mask != -1)
		mask = ntohl(ip_mask);	    
	    else {
		syslog(LOG_ERR, "%s is not a valid IP mask", ptr);	
		if (tmp)
		    free(tmp);
		return -1;
	    }
	}
	/* ip/bits mask: /24 */
	else {
	    mask_bits = atoi(ptr);
	    if ((mask_bits < 1) || (mask_bits > 30)) {
		syslog(LOG_ERR, "Invalid net mask bits (1-30): %d", mask_bits);	
		if (tmp)
		    free(tmp);
	    }	
	    /* create the mask from the number of bits */	
	    mask = 0;
	    for (i = 0; i < mask_bits; i++)
		mask |= 1 << (31 - i);
	    
	}
	
	network = from_ip & mask;
	broadcast = network | ~mask;
	
	from_ip = network + 1;
	to_ip = broadcast - 1;	
    }
    /* one host */
    else {
	ip_address = inet_addr(tmp);
	if (ip_address != -1) {
	    from_ip = ntohl(ip_address);
	    to_ip = from_ip;
	}
	else {
	    syslog(LOG_ERR, "%s is not a valid IP address", tmp);
	    if (tmp)
		free(tmp);
	    return -1;
    	}
    }
    
    if (from_ip && to_ip)
    	push_back_ip_vector(vec, from_ip, to_ip);
	
    if (tmp)
	free(tmp);	
	
    return 0;
}

/* split string with networks and add elements to the ip vector */
int split_ip_string(char *pattern, char *str, ip_vector *vec)
{
    char *ptr = NULL;
    char *tmp = NULL;
    
    if (!pattern || !str || !vec || (strlen(str) <= 2))
	return 0;

    /* behave well, use a copy */
    tmp = strdup(str);
    if (!tmp)
	return -1;

    /* remove spaces */
    clear_string(" ", &tmp);

    ptr = strtok(tmp, pattern);
    if (!ptr) {
	free(tmp);
	return -1;
    }	
    parse_network(ptr, vec);		

    while (ptr) {
	ptr = strtok(NULL, pattern);		
	if (ptr)
	    parse_network(ptr, vec);
    }
    
    free(tmp);
    
    return 0;
}

/* add a new element to the end of nameval vector */
int push_back_nameval_vector(nameval_vector *vec, char *new_name, 
			     char *new_val)
{
    nameval **tmp = NULL;
    int i = 0;

    if (!vec || !new_name || !new_val)
        return -1;
        
    /* first value of the vector */
    if (!vec->val || (vec->size <= 0)) {
        vec->val = (nameval **)malloc(VECTOR_INIT * sizeof(nameval *));
        if (!vec->val)
            return -1;
    
        vec->max = VECTOR_INIT;
        vec->size = 0;    
    }
    /* expand if memory hasn't been allocated for those number of elements */
    else if (vec->size >= vec->max) {        
        /* we don't want to lose anything in case of an error, thus tmp */
        tmp = (nameval **)realloc(vec->val, (VECTOR_GROW * vec->max)
                                         * sizeof(nameval *));
        if (!tmp)
            return -1;
            
        vec->val = tmp;
        /* we reserve some space in order to prevent allocating memory often */
        vec->max *= VECTOR_GROW;    
    }

    /* we don't want double values in the vector */
    if (vec->size > 0) {
	for (i = 0; i < vec->size; i++) {
	    if ((strcasecmp(vec->val[i]->name, new_name) == 0))
		return 0;	
	}
    }
    
    /* now we can actually add a new element */
    vec->val[vec->size] = (nameval *)malloc(sizeof(nameval));
    if (!vec->val[vec->size])
	return -1;


    vec->val[vec->size]->name = (char *)malloc(strlen(new_name) + 1);
    if (!vec->val[vec->size]->name)
	return -1;
    vec->val[vec->size]->val = (char *)malloc(strlen(new_val) + 1);
    if (!vec->val[vec->size]->val)
	return -1;

    strcpy(vec->val[vec->size]->name, new_name);
    strcpy(vec->val[vec->size]->val, new_val);

    vec->size++;
    
    return 0;
}

/* free contents of the vector */
void free_nameval_vector(nameval_vector *vec)
{
    int i;
    
    if (!vec)
        return;
    
    for (i = 0; i < vec->size; i++) {
        if (vec->val[i]->name != NULL)
            free(vec->val[i]->name);
        if (vec->val[i]->val != NULL)
            free(vec->val[i]->val);
	
        if (vec->val[i] != NULL)
            free(vec->val[i]);
    }                
    
    vec->size = 0;
    if (vec->val)
	free(vec->val);
    free(vec);
    vec = NULL;
}


/* parse hash element key=>val */
static int parse_hash_string(char *str, nameval_vector *vec)
{
    char *key = NULL;
    char *val = NULL;
    char *ptr = NULL;
    
    if (!str || !vec)
	return -1;    
    
    key = (char *)strdup(str);
    if (!key)
	return -1;
    
    if (!(ptr = strchr(key, '='))) {
	free(key);
	return -1;
    }	
    
    if (!(val = strchr(key, '>'))) {
	free(key);
	return -1;
    }	
    val++;
    
    *ptr = '\0';

    push_back_nameval_vector(vec, key, val);
    
    if (key)	
	free(key);
	
    return 0;
}

/* split string with hash elements: key1 => val1, key2 => val2 */
int split_hash_string(char *pattern, char *str, nameval_vector *vec)
{
    char *tmp = NULL;
    char *ptr = NULL;


    if (!pattern || !str || !vec || (strlen(str) <= 2))
	return 0;    

    /* behave well, use a copy */
    tmp = strdup(str);
    if (!tmp)
	return -1;

    /* remove spaces */
    clear_string(" ", &tmp);

    ptr = strtok(tmp, pattern);
    if (!ptr) {
	free(tmp);
	return -1;
    }	
    parse_hash_string(ptr, vec);		

    while (ptr) {
	ptr = strtok(NULL, pattern);		
	if (ptr)
	    parse_hash_string(ptr, vec);
    }
    
    if (tmp)
	free(tmp);
    
    return 0;
}


/* convert the given ip address in native byte order to a printable string */
char *my_ntoa(unsigned long ip)
{
    struct in_addr addr;

    if (!ip)
	return NULL;

    addr.s_addr = htonl(ip);    
    return inet_ntoa(addr);
}

