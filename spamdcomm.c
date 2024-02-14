/* $Id: spamdcomm.c, v 1.5 2010/07/01 12:00:00 farit Exp $ */

#include "spamdcomm.h"

#define INPUT_BUFF_SIZE 1024

/* extract useful info from the spam header */
static int parse_spam_header(MESSAGE *mess, char *buf)
{
    char true_false[6];


    if (!mess || !buf)
	return -1;
	
    /* convert ',' to '.' to avoid locale problems with float numbers */
    tr_string(&buf, ',', '.');	

    if (sscanf(buf, "Spam: %5s ; %f / %f", 
		true_false, &mess->spam_score, &mess->spam_threshold) == 3) {
	/* it's spam */	
	if (strcasecmp(true_false, "true") == 0) {
	    mess->is_spam = 1;
	    	    
	    return 1;
	}
	/* not spam */
	else
	    mess->is_spam = 0;			
    }		
    
    return 0;
}

/* check the mail message */
/* returns 0 - not spam, 1 - spam */
int is_spam(MESSAGE *mess) 
{
    int spam_found = 0;
    char buff[INPUT_BUFF_SIZE];   
    FILE *infile;
    char sym = '\0';
    char prev = '\0';        
    int len = 0;
    int i = 0;
    int max_header_len = 60;
    struct stat file_attr;
    char *mess_header = NULL;    
    char *ptr = NULL;    
    unsigned long content_length = 0;
    unsigned long remain_read = 0;
    int chunk_size = INPUT_BUFF_SIZE;


    /* read the message file info */
    if (stat(mess->filename, &file_attr) == -1)
        /* if file not found, say OK to cgpro */
	return 0;

    infile = fopen(mess->filename, "r");
    if (!infile)
	return 0;

    /* skip cgpro headers */
    while ((sym = fgetc(infile))) {
	len++; 
	/* there is an empty line after the header */
	if ((sym == '\n') && (prev == '\n'))
	    break;    
    
	prev = sym;	
    }

    /* don't send for scanning more than max_spamscan_size bytes */
    if ((file_attr.st_size - len) > sett->max_spamscan_size) 
	content_length = sett->max_spamscan_size;	
    else
	content_length = file_attr.st_size - len;


    /* now connect to the unix or tcp socket */
    if (sett->spamassassin_socket_type == 1) {
	if (!sett->spamassassin_host || !sett->spamassassin_port) { 
#ifdef DEBUG
	    printf("ERROR! Either spamassassin_host or spamassassin_port "
		    "wasn't defined\n"); 
#endif	
	    fclose(infile);
	    return -1;		
	}    

	/* connect to tcp port */
	if ((mess->fd = connect_tcp(sett->spamassassin_host,
				    sett->spamassassin_port)) == -1) {
#ifdef DEBUG
	    printf("ERROR! Can't connect to the spamd tcp socket."
		    "spamd host: %s, port: %d\n"
		    "Check spamassassin_host and spamassassin_port"
		    " in cgpav.conf\n", 
		    sett->spamassassin_host, sett->spamassassin_port);	    
#endif
	    fclose(infile);
	    return -1;	
	}
    }	
    /* connect to unix socket */
    else {
	if (!sett->spamassassin_socket) {
#ifdef DEBUG
	    printf("ERROR! spamassassin_socket wasn't defined\n"); 
#endif	
	    fclose(infile);
	    return -1;		
	}	    
    
	if ((mess->fd = connect_socket(sett->spamassassin_socket)) == -1) {
#ifdef DEBUG
	    printf("ERROR! Can't connect to the spamd daemon socket: %s\n"
		    "Check spamassassin_socket in cgpav.conf\n", 
		    sett->spamassassin_socket);	    
#endif
	    fclose(infile);
	    return -1;	
	}
    }

    
    /* prepare the spamd command */
    /* a header length */
    len =  strlen("SYMBOLS SPAMC/1.2\r\n")   
	    + strlen("Content-length: ") + (8 * sizeof(unsigned long)) + 2
	    /* blank line */
	    + 2;
	    
    /* if a user is found in the database */ 	    
    if (mess->user)
	len += strlen("User: ") + strlen(mess->user) + 2;
 
    if (!(mess_header = (char *)malloc(len)))
	return -1;	/* error allocating memory */

    sprintf(mess_header, "SYMBOLS SPAMC/1.2\r\n"
		         "Content-length: %lu\r\n", 
			 /* + CR */
			 (content_length + 1));
			 			 
    if (mess->user) {			 
	strcat(mess_header, "User: ");
	strcat(mess_header, mess->user);
	strcat(mess_header, "\r\n"); 
    }    
    strcat(mess_header, "\r\n"); 
    
        
    /* first send a header to the spamd */   
    if (write(mess->fd, mess_header, strlen(mess_header)) 
	!= strlen(mess_header)) {
	if (mess_header)
	    free(mess_header);
	fclose(infile);    
	return -1;
    }        

    if (mess_header)
	free(mess_header);

    /* we read a message in chunks */
    remain_read = content_length;
    if (content_length < INPUT_BUFF_SIZE)
	chunk_size = content_length;    

    memset(buff, 0, sizeof(buff));
    
    while ((remain_read > 0) && !feof(infile)) {
	if (remain_read < chunk_size)
	    chunk_size = remain_read;
	
	if (!(fread(buff, 1, chunk_size, infile))) {
	    fclose(infile);
	    return -1;
	}    
	
	remain_read -= chunk_size;
	
	/* write a message to spamd */
	if (write(mess->fd, buff, chunk_size) != chunk_size) {
	    fclose(infile);
	    return -1;	
	}    		    
    }    

    if (infile)
	fclose(infile);

    /* CR */
    if (write(mess->fd, "\n", 1) != 1) 
	return -1;		


    memset(buff, 0, sizeof(buff));
		
     /* read response */	
     while (readline(sett->av_timeout, mess->fd, 
    	    (char *)&buff, sizeof(buff)) > 0) {
            
#ifdef DEBUG
        printf("Spam scan result: %s", buff);
#endif
	
	if (strncasecmp("SPAMD/", buff, 6) == 0) {
	    if (!strstr(buff, "EX_OK")) {
		/* don't bother about errors */
		spam_found = 0;    
		break;
	    }	
	}
	else if (strncasecmp("Spam:", buff, 5) == 0) {
	    /* if 0 - it's not spam */
	    if (parse_spam_header(mess, buff) == 0)
		break;	
	    else
		spam_found = 1;	
	}
	/* save tests description */
	else if (strlen(buff) > 2) {
	    /* strip ending '\n' and '\r' */
	    if ((ptr = strchr(buff, '\r')))
		*ptr = '\0';
	    if ((ptr = strchr(buff, '\n')))
		*ptr = '\0';
	    
	    /* reserve some place for '\n\t' */
	    if (strlen(buff) > (INPUT_BUFF_SIZE - 50))
		buff[INPUT_BUFF_SIZE - 50] = '\0';
	    
	    /* insert CRs and tabs if the spam tests header is long */
	    len = max_header_len - 
		strlen("X-Spam-Status: Yes, hits=100.0 required=5.0 tests=");
	    for (ptr = buff; *ptr != '\0'; ptr++) {    
		if (*ptr == ',') {
		    ptr++;
		    /* comma index */
		    i = ptr - buff;
		    if (i > len) {
			/* move to the right */ 
			memmove(ptr + 2, ptr, strlen(buff) + 1 - i);
			/* and insert \n\t between */
			*ptr = '\n'; 
			ptr++; *ptr = '\t';
			len = i + 2 + max_header_len;
		    }
		} 
	    }
	    
	    mess->spam_message = strdup(buff);
	}
    }    	
    

    if (mess->fd != -1)
	av_disconnect(mess->fd);
    
    return spam_found;
}

