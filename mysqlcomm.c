/* $Id: mysqlcomm.c, v 1.4 2010/07/01 12:00:00 farit Exp $ */

#include "mysqlcomm.h"


/* open connection to the MySQL database */
static MYSQL *db_connect(void)
{
    /* MySQL descriptor */
    MYSQL *conn;

    if (!sett->db_username || !sett->db_password || !sett->db_database)
	return NULL;

    conn = mysql_init(NULL);
    if (!conn) {
#ifdef DEBUG
	printf("mysql_init() error\n");
#endif
	return NULL;
    }	
    
    if (!sett->db_host)
	sett->db_host = strdup("localhost");
    
    
    if (!(mysql_real_connect(conn, sett->db_host, sett->db_username, 
	sett->db_password, sett->db_database, sett->db_port, NULL, 0))) {
#ifdef DEBUG
	printf("MySQL error: %s\n", mysql_error(conn));
#endif	
	return NULL;
    }
    
    return conn;
}

/* close connection to the MySQL database */
static void db_disconnect(MYSQL *conn)
{
    if (!conn)
	return;

    mysql_close(conn);
    conn = NULL;
}

/* get the user having settings from the database */
int get_db_user(MESSAGE *mess)
{
    MYSQL *conn = NULL;
    MYSQL_RES *res_set;
    MYSQL_ROW row;
    char *sql = NULL;
    char *tmp = NULL;
    
    
    if (!mess)
	return -1;

    /* no message recipients */
    if (mess->recipients->size <= 0)
	return 0;	
	
    /* initialise */
    mess->user_spam_action = 0;
    mess->user = NULL;	

    if (!(conn = db_connect()))
	return -1;
	

    /* select the user */
    if (conn) {
	
	/* list of recipients */	
	tmp = join_vector("' OR username='", mess->recipients);
	/* no recipients */
	if (!tmp) {
	    db_disconnect(conn);
	    return 0;
	}    
	
	/* sql query */
	sql = (char *)malloc(strlen("SELECT username, value FROM userpref")
	    + strlen(" WHERE preference='spamcgpd_action' AND (username='")
	    + strlen(tmp) + strlen("') LIMIT 1") + 1);
	if (!sql) {
	    if (tmp)
		free(tmp);
	    db_disconnect(conn);	
	    return -1;
	}        
	sprintf(sql, "SELECT username, value FROM userpref"
		     " WHERE preference='spamcgpd_action'"
		     " AND (username='%s') LIMIT 1",
		tmp);
#ifdef DEBUG
	printf("SQL query: %s\n", sql);
#endif
	
	if (tmp)
	    free(tmp);	     	
    
	if (mysql_query(conn, sql) != 0) {
	    db_disconnect(conn);
	    if (sql)
		free(sql);
	    return -1;
	}    
	
	if (sql)
	    free(sql);
	
	if ((res_set = mysql_store_result(conn)) == NULL) {
	    db_disconnect(conn);
	    return -1;
	}    
	
	row = mysql_fetch_row(res_set);
	/* get results */
	if (row) {
	    if (row[0])
    		mess->user = strdup(row[0]);
	    if (row[1])
		mess->user_spam_action = atoi(row[1]);
#ifdef DEBUG
	    printf("AntiSpam user: %s\n", mess->user);
	    printf("AntiSpam user action: %d\n", mess->user_spam_action);
#endif		
	}

	mysql_free_result(res_set);	
	db_disconnect(conn);	
    }	
	
    return 0;
}




