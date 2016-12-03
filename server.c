#include <stdio.h>  
#include <stdlib.h>  
#include <errno.h>  
#include <string.h>  
#include <sys/types.h>  
#include <netinet/in.h>  
#include <sys/socket.h>  
#include <sys/wait.h>  
#include <unistd.h>  
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>  
#include <openssl/err.h>
#include <pthread.h>
#include <my_global.h>
#include <mysql.h>
  
#define MAXBUF 1024  
#define NUMT 10

#define MYSQL_USER       "project2user"  
#define SERVER_CERT_FILE "cert/server.pem"  
#define SERVER_KEY_FILE  "cert/server.key"

void finish_with_error(MYSQL *con)
{
  fprintf(stderr, "%s\n", mysql_error(con));
  mysql_close(con);
  exit(1);        
}

// This is a function helper that sends the buffer 
int send_buffer(SSL* ssl, const unsigned char* buffer, int buf_len){
   int ret;

   /* Sending the buffer length */
/*   ret = SSL_write(ssl, &buf_len, sizeof(buf_len));
   if(ret < sizeof(buf_len)){
      fprintf(stderr, "Error: SSL_write returned %d\n", ret);
      fprintf(stderr, "SSL_get_error -> %d\n", SSL_get_error(ssl, ret));
      return 1;
   }
*/
   /* Sending the buffer content */
   ret = SSL_write(ssl, buffer, buf_len);
   if(ret < buf_len){
      fprintf(stderr, "Error: SSL_write returned %d\n", ret);
      fprintf(stderr, "SSL_get_error -> %d\n", SSL_get_error(ssl, ret));
      return 1;
   }

   return 0;
}

static void process_input(MYSQL *con, SSL *ssl, BIO *client, char *buffer, char *CLIENT_NAME)
{
    int len,length = 0;
    int ret;
    char query1[] = "SELECT Id, Name, Owner FROM Files WHERE Owner=";
    char query2[] = "SELECT Location FROM Files WHERE Id=";
    char query3[] = "SELECT Name FROM Files WHERE Id=";
    char query4[] = "INSERT INTO ";
    char query5[] = "(FileId) VALUES(";
    char query6[] = "UPDATE Files SET CheckedOut=True WHERE Id=";
    char query7[] = "UPDATE Files SET CheckedOut=False, Name='";
    char query8[] = "SELECT Id, Name, Owner FROM Files WHERE Name='";
    char query9[] = "INSERT INTO Files(CheckedOut, Delegations, Owner, Name, Security, Location) Values(0,0,'";
    FILE* file;
    int msg_size;
    unsigned char* clear_buf; // buffer containing the plaintext
    char fId[MAXBUF];
    char fName[MAXBUF];
    char fSecurity[MAXBUF];
    char fLocation[MAXBUF];

    if (buffer[0] == 'a')
    {
        printf("Check-in function executing\n");
        // Send acknowledgement to client 
	BIO_write(client,buffer,strlen(buffer));

	// Get sub-menu option
	memset(buffer,0,strlen(buffer));
        len = BIO_read(client,buffer,1024);
	switch(SSL_get_error(ssl,len))
	{
	    case SSL_ERROR_NONE:
               break;
            default:
                printf("Read Problem!\n");
                exit(0);
        }
        printf("Client selected '%s'.\n",buffer);

	//Sub-menu options
 	if (buffer[0] == 'a')
    	{
	    printf("Check-in By filename (NO File UID)\n");
	    // Send acknowledgement to client 
	    BIO_write(client,buffer,strlen(buffer));

	    // Get file name from Client
	    memset(buffer,0,MAXBUF);
	    len = BIO_read(client, buffer, MAXBUF);
	    if(len <= 0)
	    {
	        strcpy(buffer, "No message");
	        len = strlen(buffer);
	    }
	    buffer[len] = '\0';
	    printf("Verifying if '%s' is in database...\n", buffer);

	    //Query database to get available options
	    char newquery8[strlen(buffer) + strlen(query8) +3];
            strcpy(newquery8,query8);
	    strcat(newquery8,buffer);
	    strcat(newquery8,"' and Owner='");
	    strcat(newquery8,CLIENT_NAME);
	    strcat(newquery8,"'");
	    printf("Query8: %s\n", newquery8);
  	    if (mysql_query(con, newquery8)) 
  	    {
      	        finish_with_error(con);
            }
  	    MYSQL_RES *result = mysql_store_result(con);
  	    if (result == NULL) 
  	    {
      	        finish_with_error(con);
  	    }
            int num_rows = mysql_num_rows(result);
	   
	    int overwrite = 0; 
            strcpy(fName,buffer);
	    if (num_rows < 1) {
		//File not in database
		BIO_write(client, "0", 2);
		printf("File not in datatbase.\n");

	    } else {
		BIO_write(client, "1", 2);
	        printf("Similar file found in database.\n");
		// Get response 
	    	memset(buffer,0,MAXBUF);
	    	len = BIO_read(client, buffer, MAXBUF);
		printf("Test");
	    	if(len <= 0)
	    	{	 
		    strcpy(buffer, "No message");
		    len = strlen(buffer);
	    	}
	        buffer[len] = '\0';	
		printf("Test2");
		if (buffer[0] == 'y') {
		    char message[] = "Overwriting file...";
		    BIO_write(client, message, strlen(message));
		    overwrite = 1;

		} else {
		    char message[] = "Saving as a copy...";
		    BIO_write(client, message, strlen(message));
		    char tempFileName[MAXBUF];
		    strcpy(tempFileName,"copy-");
		    strcat(tempFileName,fName);
		    strcpy(fName, tempFileName);
		} 		

	    }


	    // Get file name from Client (placeholder only)
	    memset(buffer,0,MAXBUF);
	    length = BIO_read(client, buffer, MAXBUF);
	    if(length <= 0)
	    {
	        strcpy(buffer, "No message");
	        length = strlen(buffer);
	    }
	    buffer[length] = '\0';
	    strcpy(fLocation,"./");
	    strcat(fLocation,CLIENT_NAME);
	    strcat(fLocation,"/");
	    strcat(fLocation,fName);

	    // Open file
	    file = fopen(fLocation, "w+");
	    if(file == NULL) {
	      fprintf(stderr, "File not found: '%s'\n", buffer);
	      exit(1);
	    }
	
	    // Get file data from Client
	    memset(buffer,0,MAXBUF);
	    length = BIO_read(client, buffer, MAXBUF);
	    if(length <= 0)
	    {
	        strcpy(buffer, "No message");
	        length = strlen(buffer);
	    }
	    buffer[length] = '\0';
	    printf("Plain text received:\n%s\n",buffer);
	
	    // Writing to file
	    fwrite(buffer, length, 1, file);
	    // Close file.
	    fclose(file);
	    printf("File Saved.\n");

	    // Send confirmation to Client
	    char message[] = "File Saved.";
	    BIO_write(client, message, strlen(message));


	    // Get SecurityFlag from Client
	    memset(buffer,0,MAXBUF);
	    length = BIO_read(client, buffer, MAXBUF);
	    if(length <= 0)
	    { 
		strcpy(buffer, "No message");
		length = strlen(buffer);
	    }
	    buffer[length] = '\0';
	    printf("Saving file with '%s' SecurityFlag\n",buffer);
	    strcpy(fSecurity,buffer);


          if (overwrite == 1) {
	        //Update Database info.
	        char newquery7[MAXBUF];
            strcpy(newquery7,query7);
	        strcat(newquery7,fName);
	        strcat(newquery7,"', Security='");
	        strcat(newquery7, fSecurity);
	        strcat(newquery7,"', Location='");
	        strcat(newquery7,fLocation);
	        strcat(newquery7,"' WHERE Id=");
	        strcat(newquery7,fId);
	        printf("Final Query:\n%s\n",newquery7);
	    
                if (mysql_query(con, newquery7)) 
  	        {
      	            finish_with_error(con);
                }


	    } else {

	        //Update Database info.
	        char newquery9[MAXBUF];
                strcpy(newquery9,query9);
	        strcat(newquery9,CLIENT_NAME); 
	        strcat(newquery9,"','");
	        strcat(newquery9, fName);
	        strcat(newquery9,"','");
	        strcat(newquery9,fSecurity);
	        strcat(newquery9,"','");
	        strcat(newquery9,fLocation);
		strcat(newquery9,"')");
	        printf("Final Query:\n%s\n",newquery9);
	    
                if (mysql_query(con, newquery9)) 
  	        {
      	            finish_with_error(con);
                }
	    }


        }
    	else if (buffer[0] == 'b')
    	{
    	    printf("Check-in By File UID\n");
            // Send acknowledgement to client 
	    BIO_write(client,buffer,strlen(buffer));
	
	    //Query database to get available options
	    char newquery[strlen(CLIENT_NAME) + strlen(query1) +3];
            strcpy(newquery,query1);
	    strcat(newquery,"'");
	    strcat(newquery,CLIENT_NAME);
	    strcat(newquery,"'");
  	    if (mysql_query(con, newquery)) 
  	    {
      	        finish_with_error(con);
            }
  	    MYSQL_RES *result = mysql_store_result(con);
  	    if (result == NULL) 
  	    {
      	        finish_with_error(con);
  	    }
            int num_rows = mysql_num_rows(result);

            /* Sending the number of rows*/
            int length = floor(log10(abs(num_rows))) + 1;
	    char snum[length];
            sprintf(snum, "%d", num_rows);
            BIO_write(client,snum,length);

            /* Build delimated file list*/
	    MYSQL_ROW row;
	    char list[MAXBUF];
	    memset(list, '\0', sizeof(list));
  	    while ((row = mysql_fetch_row(result)))
  	    {
                strncat(list, row[0], strlen(row[0]) + 1);
      	        strncat(list, ";", 2);

  	    }

	    /* Send deliminated file list */
	    BIO_write(client,list,strlen(list));
    	    mysql_free_result(result);

	    // Get the File UID
            memset(buffer,0,1024);
            len = BIO_read(client,buffer,1024);
            switch(SSL_get_error(ssl,len))
            {
                case SSL_ERROR_NONE:
                    break;
                default:
                    printf("Read Problem!\n");
                    exit(0);
            }
            printf("Client checking IN FILE UID '%s'.\n",buffer);
	    strcpy(fId,buffer);

	    //Make query for file name
	    char newquery3[strlen(buffer) + strlen(query3) +3];
            strcpy(newquery3,query3);
	    strcat(newquery3,buffer);
  	    if (mysql_query(con, newquery3)) 
  	    {
      	        finish_with_error(con);
            }
  	    result = mysql_store_result(con);
  	    if (result == NULL) 
  	    {
      	        finish_with_error(con);
  	    }
  	    row = mysql_fetch_row(result); 
	    // row[0] now contains the file name

	    //Send file name
	    BIO_write(client,row[0],strlen(row[0]));
            mysql_free_result(result); 

	    // Get SecurityFlag from Client
	    memset(buffer,0,MAXBUF);
	    length = BIO_read(client, buffer, MAXBUF);
	    if(length <= 0)
	    { 
		strcpy(buffer, "No message");
		length = strlen(buffer);
	    }
	    buffer[length] = '\0';
	    printf("Saving file with '%s' SecurityFlag\n",buffer);
	    strcpy(fSecurity,buffer);


	    // Get file name from Client
	    memset(buffer,0,MAXBUF);
	    length = BIO_read(client, buffer, MAXBUF);
	    if(length <= 0)
	    {
	        strcpy(buffer, "No message");
	        length = strlen(buffer);
	    }
	    buffer[length] = '\0';
	    printf("Saving file '%s' to local disk.\n", buffer);
	    strcpy(fName, buffer);
	    strcat(fLocation,"./");
	    strcat(fLocation,CLIENT_NAME);
	    strcat(fLocation,"/");
	    strcat(fLocation,fName);
	
	    // Open file
	    file = fopen(fLocation, "w+");
	    if(file == NULL) {
	      fprintf(stderr, "File not found: '%s'\n", buffer);
	      exit(1);
	    }
	
	    // Get file data from Server
	    memset(buffer,0,MAXBUF);
	    length = BIO_read(client, buffer, MAXBUF);
	    if(length <= 0)
	    {
	        strcpy(buffer, "No message");
	        length = strlen(buffer);
	    }
	    buffer[length] = '\0';
	    printf("Plain text received:\n%s\n",buffer);
	
	    // Writing to file
	    fwrite(buffer, length, 1, file);
	    // Close file.
	    fclose(file);
	    printf("File Saved.\n");

	    // Send confirmation to Client
	    char message[] = "File Saved.";
	    BIO_write(client, message, strlen(message));

	    //Update Database info.
	    char newquery7[MAXBUF];
            strcpy(newquery7,query7);
	    strcat(newquery7,fName);
	    strcat(newquery7,"', Security='");
	    strcat(newquery7, fSecurity);
	    strcat(newquery7,"', Location='");
	    strcat(newquery7,fLocation);
	    strcat(newquery7,"' WHERE Id=");
	    strcat(newquery7,fId);
	    printf("Final Query:\n%s\n",newquery7);
	    
            if (mysql_query(con, newquery7)) 
  	    {
      	        finish_with_error(con);
            }

    	}
        else
        {
    	    printf("Terminate function will be executed\n");
        }

    }
    else if (buffer[0] == 'b')
    {
        printf("Check-out function executing\n");
        // Send acknowledgement to client 
	BIO_write(client,buffer,strlen(buffer));

	// Query database for checkout file options
	char newquery[strlen(CLIENT_NAME) + strlen(query1) +3];
        strcpy(newquery,query1);
	strcat(newquery,"'");
	strcat(newquery,CLIENT_NAME);
	strcat(newquery,"'");
	//printf("Query: %s\n",newquery);
  	if (mysql_query(con, newquery)) 
  	{
      	    finish_with_error(con);
        }
  	MYSQL_RES *result = mysql_store_result(con);
  	if (result == NULL) 
  	{
      	    finish_with_error(con);
  	}
        int num_fields = mysql_num_fields(result);
        int num_rows = mysql_num_rows(result);

        /* Sending the number of rows*/
        int length = floor(log10(abs(num_rows))) + 1;
	char snum[length];
        sprintf(snum, "%d", num_rows);
	printf("Total Rows: %s\n",snum);
	BIO_write(client,snum,length);
  
        /* Send options and build delimated file list*/
	MYSQL_ROW row;
	char list[MAXBUF];
	memset(list, '\0', sizeof(list));
  	while ((row = mysql_fetch_row(result)))
  	{
            strncat(list, row[0], strlen(row[0]) + 1);
      	    strncat(list, ";", 2);

      	    memset(buffer, '\0', sizeof(buffer));
            strncat(buffer, row[0], strlen(row[0]) +1);
            strncat(buffer, " | ", 4);
	    strncat(buffer, row[1], strlen(row[1]) +1); 
	    strncat(buffer, " | ", 4);
	    strncat(buffer, row[2], strlen(row[2]) +1);
            printf("%s\n",buffer);
	    BIO_write(client,buffer,strlen(buffer));
  	}

	/* Send deliminated file list */
	BIO_write(client,list,strlen(list));
    	mysql_free_result(result);

        // Get the File UID
        memset(buffer,0,1024);
        len = BIO_read(client,buffer,1024);
        switch(SSL_get_error(ssl,len))
        {
            case SSL_ERROR_NONE:
                break;
            default:
                printf("Read Problem!\n");
                exit(0);
        }
        printf("Client '%s' checking out FILE UID '%s'.\n",CLIENT_NAME,buffer);

        // Store information as "checked out" in database
        char newquery4[strlen(buffer) + strlen(query4) + strlen(query5) + strlen(CLIENT_NAME) +3];
        strcpy(newquery4,query4);
	strcat(newquery4,CLIENT_NAME);
        strcat(newquery4,query5);
	strcat(newquery4,buffer);
	strcat(newquery4,")");
	printf("Query4: %s\n",newquery4);
	if (mysql_query(con, newquery4))
	{
	    finish_with_error(con);
	}
        char newquery5[strlen(buffer) + strlen(query6) +3];
        strcpy(newquery5,query6);
	strcat(newquery5,buffer);
	printf("Query5: %s\n",newquery5);
	if (mysql_query(con, newquery5))
	{
	    finish_with_error(con);
	}

	//Make query for file path
	char newquery2[strlen(buffer) + strlen(query2) +3];
        strcpy(newquery2,query2);
	strcat(newquery2,buffer);
  	if (mysql_query(con, newquery2)) 
  	{
      	    finish_with_error(con);
        }
  	result = mysql_store_result(con);
  	if (result == NULL) 
  	{
      	    finish_with_error(con);
  	}
  	row = mysql_fetch_row(result); 
	// row[0] now contains the path of the file we need to transfer
        
	/* Open the file to be sent */
	file = fopen(row[0], "r");
	if(file == NULL) {
	    fprintf(stderr, "File not found: '%s'\n", row[0]);
	    exit(1);
	}
	mysql_free_result(result);

        //Make query for file name
	char newquery3[strlen(buffer) + strlen(query3) +3];
        strcpy(newquery3,query3);
	strcat(newquery3,buffer);
  	if (mysql_query(con, newquery3)) 
  	{
      	    finish_with_error(con);
        }
  	result = mysql_store_result(con);
  	if (result == NULL) 
  	{
      	    finish_with_error(con);
  	}
  	row = mysql_fetch_row(result); 
	// row[0] now contains the file name
        
	/* Retrieve the file size */
   	fseek(file, 0, SEEK_END);
   	msg_size = ftell(file);
   	fseek(file, 0, SEEK_SET);

   	/* Reading the file to be sent */
   	clear_buf = malloc(msg_size + 1);
   	ret = fread(clear_buf, 1, msg_size, file);
   	if(ret < msg_size) {
      	    fprintf(stderr, "Error reading the file\n");
      	    exit(1);
   	}
   	clear_buf[msg_size] = '\0';
   	fclose(file);

   	printf("\nPlaintext to be sent:\n%s\n", clear_buf);

   	/* Sending the file name */
	BIO_write(client,row[0],strlen(row[0])); 
   
   	/* Sending the file */
	BIO_write(client,clear_buf, msg_size);
   	printf("File %s sent:\n   original size is %d bytes.\n", row[0], msg_size);
	mysql_free_result(result);
        
        // Receiving confirmation
	memset(buffer,0,1024);
        len = BIO_read(client,buffer,1024);
        switch(SSL_get_error(ssl,len))
        {
            case SSL_ERROR_NONE:
                break;
            default:
                printf("Read Problem!\n");
                exit(0);
        }
        printf("Client confirmed download: %s\n",buffer);

 	// Sending confirmation
        char message[] = "SUCCESS";
	BIO_write(client,message,strlen(message));
        printf("End of Check-Out\n");

    }
    else if (buffer[0] == 'c')
    {
        printf("Delegate function will be executed\n");
        // Send acknowledgement to client 
	BIO_write(client,buffer,strlen(buffer));
    }
    else if (buffer[0] == 'd')
    {
        printf("Safe-delete function will be executed\n");
        // Send acknowledgement to client 
	BIO_write(client,buffer,strlen(buffer));
    } 
    else 
    {
	printf("UNKNOWN OPTION\n");
    }
}

static void *recv_data(MYSQL *con, SSL *ssl, BIO *client)
{
    char buffer[MAXBUF];
    int len = 0;

    //Get Client Name for use
    memset(buffer,0,1024);
    len = BIO_read(client,buffer,1024);
    printf("Client '%s' CONNECTED.\n",buffer);
    char CLIENT_NAME[len+1];
    strcpy(CLIENT_NAME,buffer);
    CLIENT_NAME[len+1] = '\0';

    // Create client Table in DB if not present
    char query1[] = "CREATE TABLE IF NOT EXISTS ";
    char query2[] = "(Id INT PRIMARY KEY AUTO_INCREMENT, FileId INT)";
    char newquery[strlen(buffer) + strlen(query1) + strlen(query2) +3];
    strcpy(newquery,query1);
    strcat(newquery,buffer);
    strcat(newquery,query2);
    if (mysql_query(con, newquery)) {
      finish_with_error(con);
    }

    for(;;)
    {
        memset(buffer,0,1024);
        len = BIO_read(client,buffer,1024);
        switch(SSL_get_error(ssl,len))
        {
            case SSL_ERROR_NONE:
                break;
            default:
                printf("Read Problem!\n");
                exit(0);
        }
        if(!strcmp(buffer,"\r\n")||!strcmp(buffer,"\n"))
        {
            break;
        }
        if(buffer[0]=='q') 
        {
            break;
        }                       
        //BIO_write(client,buffer,len);
        //printf("The buffer was the following:\n");
        printf("Input Rec'd: %s\nProcessing...\n",buffer);
        process_input(con, ssl, client, buffer, CLIENT_NAME);
        //printf("That was the end of the buffer.\n");
    }
} 
      
int main(int argc, char **argv)  
{  
    char buf[MAXBUF + 1];
    char *hostname;
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sslbio, *accept, *client;
    pid_t pid;
    int len;

    if (argc != 2) {  
        printf("Usage: %s MysqlPassword\n", argv[0]);  
        printf("eg: '%s pr0ject2p@$$word'\n", argv[0]); 
        printf("(Reminder: You selected this on initial Project 2 install)\n"); 
        return -1;  
    }

    /* Mysql Initialization */
    printf("Connecting to database\n");
    MYSQL *con = mysql_init(NULL);
    if (con == NULL) 
    {
        fprintf(stderr, "%s\n", mysql_error(con));
        exit(1);
    }  

    if (mysql_real_connect(con, "localhost", MYSQL_USER, argv[1], 
          "filedata", 0, NULL, 0) == NULL) 
    {
        finish_with_error(con);
    }

  
    /* SSL Initialization */  
    SSL_library_init();  
    /* Load SSL algorithm */  
    OpenSSL_add_all_algorithms();  
    /* Load SSL error message */  
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_SSL_strings();  
    /* Generate SSL_CTX with SSLV2 or SSLV3 (SSL Content Text) */   
    ctx = SSL_CTX_new(SSLv23_server_method());  
  
    if (ctx == NULL) {  
        ERR_print_errors_fp(stdout);  
        exit(1);  
    }  
    /* Load Certificate for Client */  
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {  
        ERR_print_errors_fp(stdout);  
        exit(1);  
    }  
    /* Load Private Key */  
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {  
        ERR_print_errors_fp(stdout);  
        exit(1);  
    }  
    /* Check Private Key Validity */  
    if (!SSL_CTX_check_private_key(ctx)) {  
        ERR_print_errors_fp(stdout);  
        exit(1);  
    }  

    printf("Attempting to create BIO object... ");
    /* 0 indicate using server mode */
    ssl=SSL_new(ctx);//added
    sslbio = BIO_new_ssl(ctx, 0);
    accept = BIO_new_accept("7777");
    if(sslbio == NULL)
    {
        printf("Failed. Aborting.\n");
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        return 0;
    }

    printf("Attempting to set up BIO for SSL...\n");
    //BIO_get_ssl(sslbio, &ssl);
    BIO_set_accept_bios(accept,sslbio);

    if (BIO_do_accept(accept) <= 0)
    {
        printf("Error binding server socket\n");
    }

    
    printf("Waiting for incoming connection...\n");
    while(1)
    {
    	//Waiting for a new connection to establish//
        if(BIO_do_accept(accept) <= 0)
    	{
                    printf("BIO_do_accept(accept) <= 0\n");
        	    ERR_print_errors_fp(stdout);
        	    SSL_CTX_free(ctx);
        	    BIO_free_all(sslbio);
        	    BIO_free_all(accept);
        	    return 1;
    	}
    	client = BIO_pop(accept);

        pid = fork();
        if (pid == -1)
            printf("fork error\n");
        else if (pid == 0)
        {
            if(BIO_do_handshake(client) <= 0)
    	    {
        		printf("Handshake failed.\n");
        		ERR_print_errors_fp(stdout);
        		SSL_CTX_free(ctx);
        		BIO_free_all(sslbio);
        		BIO_free_all(accept);
        		return 1;
    	    }

            recv_data(con, ssl, client);
        }

        BIO_free(client);
    	BIO_ssl_shutdown(sslbio);
    	//exit(0);
    }
    

    BIO_ssl_shutdown(sslbio);
    BIO_free_all(sslbio);
    BIO_free_all(accept);
    SSL_CTX_free(ctx);
    mysql_close(con);
    return 0;  
} 
