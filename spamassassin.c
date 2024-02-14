/* $Id: spamassassin.c, v 1.5 2010/07/01 12:00:00 farit Exp $ */

#include "spamassassin.h"
#include "cfg.h"
#include "util.h"

#define RESULT_LEN 64

/* filedescriptor of the spamcgpavd socket */
int spam_fd = 0;


/* cleanup helper */
static int eexit(int code)
{
    if (spam_fd != -1)
	spam_disconnect(spam_fd);

    return code;
}

/* main scanning procedure */
int spam_scan_file(char *filename, float *score, float *threshold)
{
    char *request = NULL;
    char scan_result[RESULT_LEN];
    int response = 0;
    char *p = NULL;

    if (!filename || *filename == '\0')
	return eexit(0);

    memset(&scan_result, 0, sizeof(scan_result));
    
    /* connect to spamcgpavd */
    if (!sett->spamassassin_socket)
	eexit(-1);		/* no spam socket is given */

    if ((spam_fd = spam_connect(sett->spamassassin_socket)) == -1)
	return eexit(-1);	/* error connecting to spam socket */

    /* prepare spamcgpd command */
    if (!(request = (char *)malloc(1 + strlen(filename) + 2 + 1)))
	return eexit(-1);	/* error allocating memory */

    /* filename must be in the curly brackets with an \n at the end */
    sprintf(request, "{%s}\n", filename);


    if (write(spam_fd, request, strlen(request)) <= 0) {
	if (request)
	    free(request);
	return eexit(-1);	/* error writing to spam socket */
    }

    if (request)
	free(request);

    if (timeout_read(sett->av_timeout, spam_fd, (char *)&scan_result,
		     sizeof(scan_result)) <= 0)
	return eexit(-2);	/* unable to read spam response */

    /* we don't need connection anymore */
    if (spam_fd != -1)
	spam_disconnect(spam_fd);
	

    /*  printf("Scan result: %s\n", scan_result); */


    if ((p = strchr(scan_result, '\n')))
	*p = '\0';
    
    /* get response, spam_score and spam_threshold */
    p = strtok(scan_result, " |\n");
    if (p)
	response = atoi(p);    
    p = strtok(NULL, " |");
    if (p)
	*score = atof(p);
    p = strtok(NULL, " |");
    if (p)
	*threshold = atof(p);

    /* in case user added something foolish */
    if (response > 5)
	response = 0;
				
    switch (response) {
    case 0:	/* message is OK */
    case 1:	/* spam detected, default action */
    case 2:	/* spam detected, reject */
    case 3:	/* spam detected, discard */
    case 4:	/* spam detected, add header */    
    case 5:	/* spam detected, add header and store into spam folder */        
	return response;	
    default:			/* unknown result code */
	return -1;
    }

    return 0;
}

/* connect to the spam control socket */
int spam_connect(char *path)
{
    int fd = -1;		/* temporary filedescriptor */
    struct sockaddr_un s;

    memset(&s, 0, sizeof(s));	/* clean struct */

    if (!path || *path == '\0')
	return -1;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	return -1;
    s.sun_family = AF_UNIX;
    strncpy(s.sun_path, path, sizeof(s.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&s, 
                sizeof(struct sockaddr_un)) == -1) {
	/* unable to connect to the spam daemon */
	close(fd);
	fd = -1;
    }

    return fd;
}

/* close connection to the spam control socket */
void spam_disconnect(int fd)
{
    if (fd != -1)
	close(fd);
    return;
}

void spam_message(char *message)
{
    unsigned long i = 0;
    unsigned long msg_len = 0;

    if (!message)
	return;
    
    msg_len = strlen(message);	    

    for (i = 0; i < msg_len; i++) {
	switch (message[i]) {
	case '\r':
	    fputs("\\r", stdout);
	    break;
	case '\n':
	    fputs("\\n", stdout);
	    break;
	case '\t':
	    fputs("\\t", stdout);
	    break;
	case '\\':
	    fputs("\\\\", stdout);
	    break;
	case '\"':
	    fputs("\\\"", stdout);
	    break;
	case '\'':
	    fputs("\\\'", stdout);
	    break;
	default:
	    fputc(message[i], stdout);
	}
    }
}


