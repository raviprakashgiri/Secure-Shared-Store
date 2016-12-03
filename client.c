#include <stdio.h>  
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>  
#include <assert.h>  
#include <sys/socket.h>  
#include <stdlib.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <openssl/bio.h> 
#include <openssl/ssl.h>  
#include <openssl/err.h>  
#include <math.h>
 
#define BUF_SIZE   (4 * 1024)  
static char buffer[BUF_SIZE + 1];
#define NAME_SIZE  32
static char CLIENT_NAME[NAME_SIZE];
#define CA_CERT_FILE     "cert/ca.pem"  
#define printk printf
#define OK       0
#define NO_INPUT 1
#define TOO_LONG 2

char *menu[] = {
    "a - Check-in",
    "b - Check-out",
    "c - Delegate",
    "d - Safe-delete",
    "q - Terminate",
    NULL,
};

char *imenu[] = {
    "a - Init-session",
    "q - Terminate",
    NULL,
};

char *cimenu[] = {
    "a - Check-in by filename (you don't know/don't have File UID)",
    "b - Check-in by File UID",
    NULL,
};

char *smenu[] = {
    "a - CONFIDENTIALITY",
    "b - INTEGRITY",
    "c - NONE",
    NULL,
};

char *ynmenu[] = {
    "y - YES",
    "n - NO",
    NULL,
};

// STRING SPLIT - Splits string to tokens based on delimiter
char **str_split(const char* str, const char* delim, size_t* numtokens) {

    // copy the original string so that we don't overwrite parts of it
    // (don't do this if you don't need to keep the old line,
    // as this is less efficient)
    char *s = strdup(str);

    // these three variables are part of a very common idiom to
    // implement a dynamically-growing array

    size_t tokens_alloc = 1;
    size_t tokens_used = 0;
    char **tokens = calloc(tokens_alloc, sizeof(char*));
    char *token, *strtok_ctx;
    for (token = strtok_r(s, delim, &strtok_ctx);
            token != NULL;
            token = strtok_r(NULL, delim, &strtok_ctx)) {
        // check if we need to allocate more space for tokens
        if (tokens_used == tokens_alloc) {
            tokens_alloc *= 2;
            tokens = realloc(tokens, tokens_alloc * sizeof(char*));
        }
        tokens[tokens_used++] = strdup(token);
    }

    // cleanup
    if (tokens_used == 0) {
        free(tokens);
        tokens = NULL;
    } else {
        tokens = realloc(tokens, tokens_used * sizeof(char*));
    }
    *numtokens = tokens_used;
    free(s);
    return tokens;
}

///STRING SPLIT to Integer - Split comma separated string into integers
int str_to_ints(char* fstring, int features[]) {

    char **tokens2;
    size_t numtokens;

    tokens2 = str_split(fstring, ";", &numtokens);

    size_t i;
    for ( i = 0; i < numtokens; i++) {
        features[i] = atoi(tokens2[i]);
        free(tokens2[i]);
    }

    return numtokens;
}


static void *recv_data(SSL *ssl, BIO *client)
{
    int len = 0;

    memset(buffer,0,4096);
    len = BIO_read(client,buffer,4096);
    printf("%s\n",buffer);
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
        exit(0);
    }
    BIO_write(client,buffer,len);
    printf("The buffer was the following:\n");
    printf("%s\n",buffer);
    //process_input(ssl, client, buffer);
    printf("That was the end of the buffer.\n");
} 

static int getLine (char *prmpt, char *buff, size_t sz) {
    int ch, extra;

    // Get line with buffer overrun protection.
    if (prmpt != NULL) {
        printf ("%s", prmpt);
        fflush (stdout);
    }
    if (fgets (buff, sz, stdin) == NULL)
        return NO_INPUT;

    // If it was too long, there'll be no newline. In that case, we flush
    // to end of line so that excess doesn't affect the next call.
    if (buff[strlen(buff)-1] != '\n') {
        extra = 0;
        while (((ch = getchar()) != '\n') && (ch != EOF))
            extra = 1;
        return (extra == 1) ? TOO_LONG : OK;
    }

    // Otherwise remove newline and give string back to caller.
    buff[strlen(buff)-1] = '\0';
    return OK;
}

/* Function to get user input up to size 'max */
void getInput(char *input, char *greet, int max)
{
    int rc = 1;
 
    while (rc > 0) { 
    	printf("%s: \n", greet);

        rc = getLine ("Enter input> ", input, max);
        if (rc == NO_INPUT) {
            // Extra NL since my system doesn't output that on EOF.
            printf ("\nNo input\n");
        }
        if (rc == TOO_LONG) {
            printf ("Input too long [%s]\n", input);
        }
	else {
            printf ("OK [%s]\n", input);
	}
    }
    printf("You entered: %s\n", input);
   // return name;
}

void ShowCerts(SSL * ssl)  
{  
    X509 *cert;  
    char *line;  
  
    cert = SSL_get_peer_certificate(ssl);  
    if (cert != NULL) {  
        printf("certificate info:\n");  
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);  
        printf("certificate: %s\n", line);  
        free(line);  
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);  
        printf("author: %s\n", line);  
        free(line);  
        X509_free(cert);  
    } else {  
        printf("nothing\n");  
    }  
}

int clean_stdin()
{
    while (getchar()!='\n');
    return 1;
}

// Get a choice from user given array of suitable integers
int getintchoice(char *greet, int choices[], int opns)
{
    int chosen = 0;
    int selected = 0;
    int i;

    printf("\nChoice: %s\n",greet);
    do {
	
	//Get user choice
    	char c;
    	do
    	{  
            printf("Enter choice: ");

    	} while (((scanf("%d%c", &selected, &c)!=2 || c!='\n') && clean_stdin()) || selected<1 || selected>99999);

	printf("'%d' selected.\n", selected);
        
	for (i = 0; i < opns; i++) {
            if(selected == choices[i]) {
                chosen = 1;
                break;
            }
        }
        if(!chosen) {
            printf("Incorrect choice, select again.\n");
	    printf("Options include the following:\n");
	    for (i = 0; i < opns; i++) {
		printf("%d  ",choices[i]);
	    }
	    printf("\n");
        }
    } while(!chosen);
    return selected;
}

// Get a choice from user given a menu option
char getchoice(char *greet, char *choices[])
{
    int chosen = 0;
    char selected;
    char **option;

    do {
        printf("\nChoice: %s\n",greet);
        option = choices;
        while(*option) {
            printf("%s\n",*option);
            option++;
        }
        selected = getchar();
        getchar();
        option = choices;
        while(*option) {
            //printf("The option is %c\n", *option[0]);
            if(selected == *option[0]) {
                chosen = 1;
                break;
            }
            option++;
        }
        if(!chosen) {
            printf("Incorrect choice, select again\n");
        }
    } while(!chosen);
    return selected;
}

void choiceProcess (BIO *sslbio, char *buffer, char choice)
{
    int length;

    memset(buffer, '\0', BUF_SIZE);
    buffer[0] = choice;
    BIO_write(sslbio, buffer, strlen(buffer));
    length = BIO_read(sslbio, buffer, BUF_SIZE);
    if(length <= 0)
    {
        strcpy(buffer, "No message");
        length = strlen(buffer);
    }
    buffer[length] = '\0';
    printf("'%s', acknowledged by server.\n", buffer);
}

void clientTerminate (BIO *sslbio, char *buffer)
{
    buffer[0] = 'q';
    BIO_write(sslbio, buffer, strlen(buffer));
    memset(buffer, '\0', BUF_SIZE);
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
  

// This is a function that sends a file to the server
int send_file(const char* file_name, BIO *sslbio) {

   FILE* file;      // pointer to the file to be sent
   int msg_size;          // size of the file to be sent

   unsigned char* clear_buf; // buffer containing the plaintext
   int ret;

   /* Open the file to be sent */
   file = fopen(file_name, "r");
   if(file == NULL) {
      fprintf(stderr, "File not found: '%s'\n", file_name);
      return 1;
   }

   /* Retrieve the file size */
   fseek(file, 0, SEEK_END);
   msg_size = ftell(file);
   fseek(file, 0, SEEK_SET);

   /* Reading the file to be sent */
   clear_buf = malloc(msg_size + 1);
   ret = fread(clear_buf, 1, msg_size, file);
   if(ret < msg_size) {
      fprintf(stderr, "Error reading the file\n");
      return 1;
   }
   clear_buf[msg_size] = '\0';
   fclose(file);

   printf("\nPlaintext to be sent:\n%s\n", clear_buf);

   /* Sending the file name */
   BIO_write(sslbio, file_name, strlen(file_name));

   /* Sending the file */
   BIO_write(sslbio, clear_buf, msg_size);

   printf("\nFile %s sent:\n   original size is %d bytes.\n", file_name, msg_size);

   return 0;
}

// This is a function that checks in a file to the server
int checkin_file(SSL* ssl, BIO *sslbio, char *buffer) {
    char choice;
    int ret,length;    
    char filename[BUF_SIZE];

    choice = getchoice("Please select an action", cimenu);
    printf("You have chosen: %c\n", choice);
  	
    if (choice == 'a')
    {
	printf("Check-in By filename (NO File UID)\n");
	choiceProcess (sslbio, buffer, choice);

	getInput(filename, "Enter the filename \n (e.g., 'testfile.txt')", 32);

   	/* Sending the file name */
   	BIO_write(sslbio, filename, strlen(filename));

	// Receive server status 
        memset(buffer,0,4096);
    	length = BIO_read(sslbio, buffer, BUF_SIZE);
    	if(length <= 0)
    	{
    	    strcpy(buffer, "No message");
    	    length = strlen(buffer);
    	}
    	buffer[length] = '\0';
	printf("BUffer: %s",buffer);
	if (buffer[0] == '0') {
	    printf("Server confirms file is not already stored; storing file now.\n");	
	} else {
	    printf("Similiar file found in database...\n");
	    choice = getchoice("Overwrite your old file?", ynmenu);
	    if ( choice == 'y' ) {
		char answer[] = "yes";
		BIO_write(sslbio,answer,strlen(answer));
	     } else { 
	        char answer[] = "no";
		BIO_write(sslbio, answer, strlen(answer));
	     }
	}


	// Send the file to the server
	ret = send_file(filename, sslbio);

        // Get Server confirmation
    	memset(buffer,0,4096);
    	length = BIO_read(sslbio, buffer, BUF_SIZE);
    	if(length <= 0)
    	{
    	    strcpy(buffer, "No message");
    	    length = strlen(buffer);
    	}
    	buffer[length] = '\0';
        printf("Server confirmation: %s\n",buffer);

	char SecurityFlag[16];
	choice = getchoice("Select 'SecurityFlag' for this file",smenu);
	if (choice == 'a') {
	    strcpy(SecurityFlag, "CONFIDENTIALITY");
	} else if (choice == 'b') {
	    strcpy(SecurityFlag, "INTEGRITY");
	} else {
	    strcpy(SecurityFlag, "NONE");
	}

	printf("SecurityFlag confirmed as '%s'\n",SecurityFlag);
	BIO_write(sslbio, SecurityFlag, strlen(SecurityFlag));



    } // option 'a' ends



    else if (choice == 'b')
    {
    	printf("Check-in By File UID\n");
        choiceProcess (sslbio, buffer, choice);
	
	// Receive the number of File UID options 
        memset(buffer,0,4096);
    	length = BIO_read(sslbio, buffer, BUF_SIZE);
    	if(length <= 0)
    	{
    	    strcpy(buffer, "No message");
    	    length = strlen(buffer);
    	}
    	buffer[length] = '\0';
    	printf("You have access to %s file(s) on the server that are\n", buffer);
	printf("available for you to check in by File UID.\n"); 
    	int opns = atoi(buffer);
    
    	if ( opns < 1 ) {
    	    //No files to choose from.
    	    printf("You have access to ZERO files stored at server...\n");
	    printf("Unable to check-in by File UID: Choose a different option.\n");
	    printf("Recommend check-in by filename instead to receive new UID from server.\n");
	    exit(1);
	}

	// Receive deliminated list of option numbers
	memset(buffer,0,4096);
    	length = BIO_read(sslbio, buffer, BUF_SIZE);
    	if(length <= 0)
    	{
            strcpy(buffer, "No message");
            length = strlen(buffer);
    	}
    	buffer[length] = '\0';

    	// Tokenize options
    	int options[opns];
    	int numtokens = str_to_ints(buffer, options);
    
    	// Select Option, i.e., file UID choice
    	int filechoice =  getintchoice("Enter File UID you wish to check-in", options, opns);
    	length = floor(log10(abs(filechoice))) + 1;
    	char sfile[length];
    	sprintf(sfile, "%d", filechoice);

    	// Send File UID to Server
    	BIO_write(sslbio, sfile, length);

	// Receive File Name from Server
	memset(buffer,0,4096);
    	length = BIO_read(sslbio, buffer, BUF_SIZE);
    	if(length <= 0)
    	{
    	    strcpy(buffer, "No message");
    	    length = strlen(buffer);
    	}
    	buffer[length] = '\0';

	printf("Preparing to check-in File UID '%d', Filename '%s'\n",filechoice,buffer);
	printf("Has your filename changed since last upload? (Is it different than listed here?)\n");
	choice = getchoice("Please select an action", ynmenu);

	char filename[BUF_SIZE];

	if (choice == 'y') 
	{
	    getInput(filename, "Enter the new filename \n (e.g., 'testfile.txt')", 32);
	}
	else //File name hasn't changed 
	{
	    strcpy(filename,buffer);
	}

	char SecurityFlag[16];
	choice = getchoice("Select 'SecurityFlag' for this file",smenu);
	if (choice == 'a') {
	    strcpy(SecurityFlag, "CONFIDENTIALITY");
	} else if (choice == 'b') {
	    strcpy(SecurityFlag, "INTEGRITY");
	} else {
	    strcpy(SecurityFlag, "NONE");
	}

	printf("SecurityFlag confirmed as '%s'\n",SecurityFlag);
	BIO_write(sslbio, SecurityFlag, strlen(SecurityFlag));
	
	// Send the file to the server
	ret = send_file(filename, sslbio);

        // Get Server confirmation
    	memset(buffer,0,4096);
    	length = BIO_read(sslbio, buffer, BUF_SIZE);
    	if(length <= 0)
    	{
    	    strcpy(buffer, "No message");
    	    length = strlen(buffer);
    	}
    	buffer[length] = '\0';
        printf("Server confirmation: %s\n",buffer);

    }
    else
    {
    	printf("Terminate function will be executed\n");
    }
}



// This is a function that checks out a file from the server
// - RETURNS 0 in case of success, 1 otherwise
int checkout_file(SSL* ssl, BIO *sslbio, char *buffer) {

   FILE* file;            // pointer to the file to be received
   int ret;
   int length;

    // Sending the client name
   // BIO_write(sslbio, CLIENT_NAME, strlen(CLIENT_NAME));

    // Receive number of options
    memset(buffer,0,4096);
    length = BIO_read(sslbio, buffer, BUF_SIZE);
    if(length <= 0)
    {
        strcpy(buffer, "No message");
        length = strlen(buffer);
    }
    buffer[length] = '\0';
    printf("\nSelect file number to check out file.\n");
    printf("You have %s option(s):\n", buffer); 
    int opns = atoi(buffer);
    
    if ( opns < 1 ) {
        //No files to choose from.
        printf("You have ZERO files stored at server...\n");
	printf("Unable to check-out file: Choose a different option.\n");
	exit(1);
    }

    // If files are present, receive file options
    printf("\nFILE UID | FILE NAME | FILE OWNER\n");
    int i;
    for (i = 0; i < opns; i++) {
        memset(buffer,0,4096);
        length = BIO_read(sslbio, buffer, BUF_SIZE);
        if(length <= 0)
        {
            strcpy(buffer, "No message");
            length = strlen(buffer);
        }
        buffer[length] = '\0';
        printf("%s\n", buffer); 
    }

    // Receive deliminated list of option numbers
    memset(buffer,0,4096);
    length = BIO_read(sslbio, buffer, BUF_SIZE);
    if(length <= 0)
    {
        strcpy(buffer, "No message");
        length = strlen(buffer);
    }
    buffer[length] = '\0';

    // Tokenize options
    int options[opns];
    int numtokens = str_to_ints(buffer, options);
    
    // Select Option, i.e., file UID choice
    int filechoice =  getintchoice("Select FILE UID to checkout", options, opns);
    length = floor(log10(abs(filechoice))) + 1;
    char sfile[length];
    sprintf(sfile, "%d", filechoice);

    // Send File UID to Server
    BIO_write(sslbio, sfile, length);

    // Get file name from Server
    memset(buffer,0,4096);
    length = BIO_read(sslbio, buffer, BUF_SIZE);
    if(length <= 0)
    {
        strcpy(buffer, "No message");
        length = strlen(buffer);
    }
    buffer[length] = '\0';
    printf("Saving file '%s' to local disk.\n", buffer);

    // Open file
    file = fopen(buffer, "w+");
    if(file == NULL) {
      fprintf(stderr, "File not found: '%s'\n", buffer);
      return 1;
    }

    // Get file data from Server
    memset(buffer,0,4096);
    length = BIO_read(sslbio, buffer, BUF_SIZE);
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

    // Send confirmation to server
    char message[] = "File Saved.";
    BIO_write(sslbio, message, strlen(message));

    // Receive confirmation from server
    memset(buffer,0,4096);
    length = BIO_read(sslbio, buffer, BUF_SIZE);
    if(length <= 0)
    {
        strcpy(buffer, "No message");
        length = strlen(buffer);
    }
    buffer[length] = '\0';
    printf("File Successfully Checked Out: %s\n",buffer);

    return 0;
}
  
int main(int argc, char **argv)  
{
    BIO *sslbio;
    SSL_CTX *ctx;  
    SSL *ssl;  
    //SSL_METHOD *meth;  
    unsigned long totl;  
    int i, p;
    char hostname[BUF_SIZE + 1];
    char server[16];
    char choice;
    int ret;    

  
    if (argc != 2) {  
        printf("Usage: %s ClientName\n", argv[0]);  
        printf("eg: '%s client1'\n", argv[0]);  
        return -1;  
    }

    if (strlen(argv[1]) >= NAME_SIZE) {
        fprintf(stderr, "%s is too long! \nPick a shorter client name.\n",argv[1]);
    } else {
        strcpy(CLIENT_NAME, argv[1]);    
    }
    printf("client name: %s\n", CLIENT_NAME);

    /* Formatting required certificates for client ...
       certificates are matched to client with file names */
    int length = strlen(CLIENT_NAME) + 10;
    char CLIENT_CERT_FILE2[length];
    strcpy(CLIENT_CERT_FILE2, "cert/");
    strcat(CLIENT_CERT_FILE2, CLIENT_NAME);
    strcat(CLIENT_CERT_FILE2, ".pem");
    printf("This client CERT file is required: %s\n", CLIENT_CERT_FILE2);
    // Checking for required certificate
    if( access( CLIENT_CERT_FILE2, F_OK ) != -1 ) {
    // file exists
	printf("CERT file verified present\n");
    } else {
    // file doesn't exist
	printf("CERT NOT FOUND....\n"
		"Perhaps this client does not have valid\n"
		"certificates present at this location\n"
		">>> ./%s\n",CLIENT_CERT_FILE2);
	exit(4);
    }
    char CLIENT_KEY_FILE2[length];
    strcpy(CLIENT_KEY_FILE2, "cert/");
    strcat(CLIENT_KEY_FILE2, CLIENT_NAME);
    strcat(CLIENT_KEY_FILE2, ".key");
    printf("This client KEY file is required: %s\n", CLIENT_KEY_FILE2);
    // Checking for required certificate
    if( access( CLIENT_KEY_FILE2, F_OK ) != -1 ) {
    // file exists
	printf("KEY file verifier present\n\n");
    } else {
    // file doesn't exist
	printf("KEY NOT FOUND....\n"
		"Perhaps this client does not have valid"
		"certificates present at this location\n"
		">>> ./%s\n",CLIENT_KEY_FILE2);
	exit(4);
    }

    /* Give initial menu to user; get hostname for connection */
    choice = getchoice("Please select an action", imenu);
    printf("You have chosen: %c\n", choice);
    if (choice == 'q')
    {
	printf("Ending Program... Goodbye.\n");
    } 
    else // choice == 'a' 
    {
	printf("Initializing connection...\n");
    
	// NOTE: 45 is the max length of a IPv4 address
        getInput(server, "Enter server hostname to connect \n (e.g., '127.0.0.1')", 15);
    	SSL_library_init();  
    	ERR_load_BIO_strings();
    	ERR_load_SSL_strings();  
    	SSL_load_error_strings();
    	OpenSSL_add_all_algorithms();
	ctx = SSL_CTX_new(SSLv23_client_method()); 
//    	ctx = SSL_CTX_new(SSLv3_method());
    	  
    	//ctx = SSL_CTX_new(meth);  
    	assert(ctx != NULL);  
          
    	/* Verify the server */  
    	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);  
    	/* Load CA Certificate */  
    	if (!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL)) {  
            printf("Load CA file failed.\r\n");  
            //goto free_ctx;
            BIO_free_all(sslbio);
            SSL_CTX_free(ctx);
            return 0;
        }  
  

    	/* Load Client Certificate with Public Key */  
    	if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE2, SSL_FILETYPE_PEM) <= 0) {  
            ERR_print_errors_fp(stdout);  
            printf("ssl_ctx_use_certificate_file failed.\r\n");  
            //goto free_ctx;
            BIO_free_all(sslbio);
            SSL_CTX_free(ctx);
            return 0;  
        }  
  
      
    	/* Load Private Key */  
    	if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY_FILE2, SSL_FILETYPE_PEM) <= 0) {  
            ERR_print_errors_fp(stdout);  
            printf("ssl_ctx_use_privatekey_file failed.\r\n");  
            //goto free_ctx;
            BIO_free_all(sslbio);
            SSL_CTX_free(ctx);
            return 0;
        }  
  
      // Extra features for security...

    	/* Check the validity of Private Key */  
    	if (!SSL_CTX_check_private_key(ctx)) {  
            ERR_print_errors_fp(stdout);  
            printf("ssl_ctx_check_private_key failed.\r\n");  
            //goto free_ctx;
            BIO_free_all(sslbio);
            SSL_CTX_free(ctx);
            return 0;  
    	}

    	/* Create the connection */
    	sslbio = BIO_new_ssl_connect(ctx);
    	/* Get SSL from sslbio */
    	BIO_get_ssl(sslbio, &ssl);
    	/* Set the SSL mode into SSL_MODE_AUTO_RETRY */
    	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
 
    	//////////////////////////////////////////////////
    	// NOTE: Port# hardcoded here; change if necessary
    	////////////////////////////////////////////////// 
    	BIO_set_conn_port(sslbio, "7777");
    	BIO_set_conn_hostname(sslbio, server);
	
	/* Request Connection */
	if(BIO_do_connect(sslbio) <= 0)
    	{
            fprintf(stderr, "Error attempting to connect\n");
            ERR_print_errors_fp(stderr);
            BIO_free_all(sslbio);
            SSL_CTX_free(ctx);
            return 0;
    	}
    	else
    	{
            printf("Connection to server successful!\n");
    	}

    	/* Verify Server Certificate Validity */
    	if(SSL_get_verify_result(ssl) != X509_V_OK)
    	{
            printf("Certificate Verification Error: %ld\n", SSL_get_verify_result(ssl));
            BIO_free_all(sslbio);
            SSL_CTX_free(ctx);
            return 0;
    	}
    	else
    	{
    	    printf("verify server cert successful\n");
    	}

    	//Send hostname to server
    	printf("Sending client name to server.\n");
    	BIO_write(sslbio, CLIENT_NAME, strlen(CLIENT_NAME));
  
    	do
    	{
    	    choice = getchoice("Please select an action", menu);
    	    printf("You have chosen: %c\n", choice);
	
	    if (choice == 'a')
	    {
        	printf("Check-in function will be executed\n");
                choiceProcess (sslbio, buffer, choice);
                ret = checkin_file(ssl, sslbio, buffer);
        }
        else if (choice == 'b')
        {
            printf("Check-out function will be executed\n");
            choiceProcess (sslbio, buffer, choice);
		    ret = checkout_file(ssl, sslbio, buffer);
        }
            else if (choice == 'c')
            {
                printf("Delegate function will be executed\n");
                choiceProcess (sslbio, buffer, choice);
            }
            else if (choice == 'd')
            {
                printf("Safe-delete function will be executed\n");
                choiceProcess (sslbio, buffer, choice);
            }
            else
            {
                printf("Terminate function will be executed\n");
            }

        } while (choice != 'q');

        /* Terminate the connection by sending message */
        clientTerminate (sslbio, buffer);

        /* Close the connection and free the context */
        BIO_ssl_shutdown(sslbio);
        BIO_free_all(sslbio);
    	SSL_CTX_free(ctx);
    }

    return 0;  
} 
