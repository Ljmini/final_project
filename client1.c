#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <dirent.h>
#include <error.h>

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <pthread.h>
#include <openssl/conf.h>
#include <openssl/sha.h>


#include "readnwrite.h"
#include "aesenc.h"
#include "msg.h"


#define NAME_SIZE 20
#define PASS_SIZE 30

void *recv_msg(void *arg);		// receive
void *send_msg(void *arg);		// send   		--> parallel
void error_handling(char *message);
void digest_message(const unsigned char*message, size_t message_len,unsigned char **digest,unsigned *digest_len);
void aes_file_enc_test(char* iFilename, char oFilename[NAME_SIZE], unsigned char key[AES_KEY_128], unsigned char iv[AES_KEY_128],int *clnt_sock);
//char name[NAME_SIZE] ="[DEFULT]";


typedef struct {
	unsigned char key[AES_KEY_128];	
	unsigned char iv[AES_KEY_128];
	int sock;
}param;


int main(int argc, char *argv[])
{
	int sock;
	int cnt_i;
	int len;
	int name_len, password_len;
	int i;
	int ciphertext_len;
	int plaintext_len;
	int n;

	struct sockaddr_in serv_addr;
	
	pthread_t snd_thread, rcv_thread;
	void *thread_return;
	
	param *first = (param*)malloc(sizeof(param));
	
	// RSAES
	APP_MSG msg_in;
	APP_MSG msg_out;
	
	unsigned char key[AES_KEY_128]={0x00,};	
	unsigned char iv[AES_KEY_128]={0x00,};
	unsigned char plaintext[BUFSIZE+AES_BLOCK_LEN] = {0x00,};
	unsigned char ID[NAME_SIZE] ={0x00,};
	unsigned char PW[PASS_SIZE] ={0x00,};
	unsigned char buf[BUFSIZE+AES_BLOCK_LEN]={0x00,};

	// HASH
	unsigned char *digest = NULL;
	unsigned int digest_len;
	
	
	BIO *rpub = NULL;
	RSA *rsa_pubkey = NULL;
	
	RAND_poll();
	RAND_bytes(key,sizeof(key));
	

	
	for(cnt_i=0;cnt_i<AES_KEY_128;cnt_i++)
	{
		iv[cnt_i] = (unsigned char)cnt_i;
	}
	
	// RSAES
	if(argc!=3){
		printf("Usage : %s <IP> <port> \n",argv[0]);
		exit(1);
	}
	
	sock = socket(PF_INET,SOCK_STREAM,0);
	memset(&serv_addr,0,sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port=htons(atoi(argv[2]));
	
	if(connect(sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1)
		error_handling("connect() error");
	
	
	// setup process
	// setup process
	
	// sending PUBLIC_KEY_REQUEST msg
	memset(&msg_out,0,sizeof(msg_out));
	msg_out.type = PUBLIC_KEY_REQUEST;
	msg_out.type =htonl(msg_out.type);
	
	n = writen(sock,&msg_out, sizeof(APP_MSG));
	if(n==-1)
		error_handling("writen() error");
	else{
		printf("[SEND PUBLIC_KEY REQUEST OK.]\n");
	}
	
	// receiving PUBLIC_KEY msg
	memset(&msg_in,0,sizeof(msg_out));
	n = readn(sock,&msg_in,sizeof(APP_MSG));
	msg_in.type = ntohl(msg_in.type);
	msg_in.msg_len = ntohl(msg_in.msg_len);
	
	if(n==-1)
		error_handling("readn() error");
	else if(n==0)
		error_handling("reading EOF");
	else
		printf("[RECEIVE PUBLIC_KEY OK.]\n");
		
	if(msg_in.type != PUBLIC_KEY){
		error_handling("message error");
	}
	else{
		//BIO_dump_fp(stdout,(const char*)msg_in.payload,msg_in.msg_len);
		rpub = BIO_new_mem_buf(msg_in.payload,-1);
		//BIO_write(rpub,msg_in.payload,msg_in.msg_len);
		if(!PEM_read_bio_RSAPublicKey(rpub,&rsa_pubkey,NULL,NULL)){
			error_handling("PEM_read_bio_RSAPublicKey() error");
		}
	}
	
	// sending ENCRYPTED_KEY msg
	memset(&msg_out, 0, sizeof(msg_out));
	msg_out.type = ENCRYPTED_KEY;
	msg_out.type = htonl(msg_out.type);
	
	msg_out.msg_len = RSA_public_encrypt(sizeof(key),key,msg_out.payload,rsa_pubkey,RSA_PKCS1_OAEP_PADDING);
	msg_out.msg_len = htonl(msg_out.msg_len);
	
	n = writen(sock,&msg_out,sizeof(APP_MSG));
	if(n==-1)
		error_handling("writen() error");
	else{
		printf("[SEND ENCRYPTED SESSIONG KEY OK.]\n");
		/*
		for(cnt_i=0;cnt_i<sizeof(key);cnt_i++){
			printf("%02x ",key[cnt_i]);
		}
		*/
	}
	
	memcpy(first->key,key,sizeof(key));
	memcpy(first->iv,iv,sizeof(iv));
	first->sock = sock;
		
	//getchar();
	printf("\n");
	// ID/PW send to server
	n = readn(sock, &msg_in,sizeof(APP_MSG));
	if(n==-1){
			error_handling("readn() error");
			//break;
	}
	else if(n==0)
		printf("size is 0\n");
			
	msg_in.type = ntohl(msg_in.type);
	switch(msg_in.type){
		case ID_PASSWORD:
			printf("[ID] : ");
			if(fgets(ID, NAME_SIZE,stdin) == NULL){
				printf("names is not inputted\n");
			}
			name_len = strlen(ID);
			if(ID[name_len-1]=='\n'){
				ID[name_len-1] = ' ';
			}
			if(strlen(ID)==0){
				//break;
			}
			printf("[PASSWORD] : ");
			// PASSWORD
			if(fgets(PW,PASS_SIZE,stdin)== NULL){
				printf("password is not inputted\n");
			}
			password_len = strlen(PW);
			if(PW[password_len-1]=='\n'){
				PW[password_len-1] = ' ';
			}
			if(strlen(PW)==0){
				//break;
			}
			// HASH for password
			digest_message(PW,password_len-1,&digest,&digest_len);
			
			len = name_len + password_len + digest_len;
			for(i =0;i<name_len;i++)
			{
				plaintext[i] = ID[i];
			}
			for(i=name_len;i<name_len + password_len;i++)
			{
				plaintext[i] = PW[i-name_len];
			}
			for(i= name_len + password_len;i<len;i++)
			{
				plaintext[i] = digest[i-(name_len + password_len)];
			}
			//printf("client len : %d\n",len);
			//printf("client : ID/PW hash! : ");
			//printf("name_len : %d , password_len : %d, hash_len : %d\n",name_len,password_len,digest_len);
			//printf("len : %d\n",len);
			// E(ID || PW || Hash(PW) )
			/*for(i=0;i<len;i++)
			{
				printf("%x ",plaintext[i]);
			}
			printf("\n client hash : ");
			for(i=0;i<digest_len;i++)
			{
				printf("%x ",digest[i]);
			}
			*/
			memset(&msg_out,0,sizeof(msg_out));
			msg_out.type = ID_PASSWORD;
			msg_out.type = htonl(msg_out.type);
			
			ciphertext_len = encrypt((unsigned char*)plaintext, len, key, iv, msg_out.payload);
			//printf("1. ciphertext_len : %d\n",ciphertext_len);
			msg_out.msg_len = htonl(ciphertext_len);
			
			n = writen(sock,&msg_out,sizeof(APP_MSG));
			if(n==-1){
				error_handling("ID/pw write() error");
			}
			else{
				//printf("success send ID/PW\n");
				//printf("write size is :%d \n",n);
			}	
	}
	// respond about ID/PW
	n = readn(sock,&msg_in,sizeof(APP_MSG));
	if(n==-1){
			error_handling("readn() error");
		}
	else if(n==0){
		printf("read size is : %d\n",n);
	}	
	msg_in.type = ntohl(msg_in.type);
	msg_in.msg_len = ntohl(msg_in.msg_len);
	msg_in.cnt = ntohl(msg_in.cnt);
	for(i=0;i<BUFSIZE+AES_BLOCK_SIZE;i++)
	{
		plaintext[i] = 0x00;
	}	
	switch(msg_in.type){
		case ENCRYPTED_MSG:
			//printf("[Enc_ID_PW_Msg ] : ");
			//BIO_dump_fp(stdout,(const char*)msg_in.payload,msg_in.msg_len);
			plaintext_len = decrypt(msg_in.payload,msg_in.msg_len,key,iv,(unsigned char*)plaintext);
			//printf("\n");
			//printf("Dec_ID_PW_Msg ] : ");
			//BIO_dump_fp(stdout,(const char*)plaintext,plaintext_len);
			//printf("\n");
			
	}
	//printf("plaintext : %s\n",plaintext);
	//printf("client plinatext_len : %d\n",plaintext_len);
	memset(buf,0x00,BUFSIZE+AES_BLOCK_LEN);
	for(i=0;i<plaintext_len;i++){
		buf[i] = plaintext[i];
	}
	if(strcmp(buf,"deny")==0){
		printf("[CAN'T ACCESS]\n");
		close(sock);
		exit(1);
	}
	
	printf("\n");
	printf("================[Connectd with server]================\n\n");
	pthread_create(&snd_thread,NULL,send_msg,(void*)first);
	pthread_create(&rcv_thread,NULL,recv_msg,(void*)first);
	pthread_join(snd_thread,&thread_return);
	pthread_join(rcv_thread,&thread_return);
	close(sock);
	
	return 0;
	
}

void digest_message(const unsigned char*message, size_t message_len,unsigned char **digest,unsigned *digest_len)
{
	EVP_MD_CTX *mdctx;
	
	if((mdctx = EVP_MD_CTX_create()) == NULL)
		handleErrors();
	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handleErrors();
	if(1 != EVP_DigestUpdate(mdctx,message,message_len))
		handleErrors();
	if((*digest = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		handleErrors();
	
	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors();
		
	EVP_MD_CTX_destroy(mdctx);
}

void *send_msg(void *arg)
{
	
	//printf("send_msg start!\n");
	param *second = (param*)malloc(sizeof(param));
	second = arg;
	
	int sock = second->sock;
	unsigned char key[AES_KEY_128]={0x00,};	
	unsigned char iv[AES_KEY_128]={0x00,};
	
	unsigned char filename1[NAME_SIZE] = {0x00,};
	unsigned char filename2[NAME_SIZE] ={0x00,};
	
	memcpy(key,second->key,sizeof(key));
	memcpy(iv,second->iv,sizeof(iv));
	
	APP_MSG msg_out;
	
	int n,j,i;
	int ciphertext_len;
	int len;
	char plaintext[BUFSIZE] = {0x00,};
	char list_name[BUFSIZE+AES_BLOCK_LEN] = {0x00,};
	int filename1_len, filename2_len;
	
	
	while(1)
	{
		// input a message
		printf("\n");
		printf("[Input a message] : ");
		memset(plaintext,0x00,BUFSIZE + AES_BLOCK_LEN);
		if(fgets(plaintext, BUFSIZE,stdin) == NULL)
			break;
		
		// removing '\n' character
		len = strlen(plaintext);
		if(plaintext[len-1]=='\n'){
			plaintext[len-1] = '\0';
		}
		if(strlen(plaintext)==0){
			break;
		}
		printf("1. plaintext_len : %d\n",len);
		
		
		// upload
		if(plaintext[0] == 0x75){
			printf("upload!!\n");
			char *arr[3] ={NULL,};
			char *ptr = strtok(plaintext," ");
			j = 0;
			while(ptr != NULL)
			{
				arr[j] = ptr;
				j++;
				ptr = strtok(NULL," ");
			}
			strcpy(filename1,arr[1]);
			filename1_len = strlen(arr[1]);
			strcpy(filename2,arr[2]);
			filename2_len = strlen(arr[2]);
			
			printf("[CLIENT filename] : %s\n",filename1);
			printf("[SERVER filename] : %s\n",filename2);
			
			//  open file
			aes_file_enc_test(filename1, filename2, key, iv, &sock);
			printf("done upload!\n");
		}
		else{
			memset(&msg_out,0,sizeof(msg_out));
			msg_out.type = ENCRYPTED_MSG;
			msg_out.type = htonl(msg_out.type);
			
			ciphertext_len = encrypt((unsigned char*)plaintext, len, key, iv, msg_out.payload);
			msg_out.msg_len = htonl(ciphertext_len);
			
			//printf("1. client_plaintext : %s\n",plaintext);	
			// sending the inputed message
			//for(i=0;i<
			n = writen(sock,&msg_out,sizeof(APP_MSG));
			if(n==-1){
				error_handling("write() error");
				break;
			}
		}
		
	}
	printf("send done!");
	return NULL;
}


void *recv_msg(void *arg)
{
	
	//printf("recv_msg start!\n");
	param *second = (param*)malloc(sizeof(param));
	second = arg;
	//printf("1\n");
	int sock = second->sock;
	unsigned char key[AES_KEY_128];	
	unsigned char iv[AES_KEY_128];
	
	unsigned char filename[NAME_SIZE]={0x00,};
	unsigned char file[BUFSIZE+AES_BLOCK_LEN]={0x00,};
	char list_name[BUFSIZE+AES_BLOCK_LEN] = {0x00,};
	char plaintext[BUFSIZE+AES_BLOCK_LEN] = {0x00,};
	
	int filename_len;
	int file_len;
	int plaintext_len;
	int n;
	int j,i;
	int cnt;
	
	memcpy(key,second->key,sizeof(key));
	memcpy(iv,second->iv,sizeof(iv));
	
	APP_MSG msg_in;
	
	while(1)
	{
		//printf("received message : ");
		// receiving a message from the server
		n = readn(sock, &msg_in,sizeof(APP_MSG));
		
		//printf("1. received message size : %d\n",n);
		
		if(n==-1){
			error_handling("readn() error");
			break;
		}
		else if(n==0)
			break;
			
		msg_in.type = ntohl(msg_in.type);
		msg_in.msg_len = ntohl(msg_in.msg_len);
		msg_in.cnt = ntohl(msg_in.cnt);
		
		for(i=0;i<BUFSIZE+AES_BLOCK_SIZE;i++)
		{
			plaintext[i] = 0x00;
		}	
		
		switch(msg_in.type){
			case ENCRYPTED_MSG:
				printf("[Enc_Msg] : ");
				BIO_dump_fp(stdout,(const char*)msg_in.payload,msg_in.msg_len);
				plaintext_len = decrypt(msg_in.payload,msg_in.msg_len,key,iv,(unsigned char*)plaintext);
				printf("\n");
				printf("[Dec_Msg] : ");
				BIO_dump_fp(stdout,(const char*)plaintext,plaintext_len);
				printf("\n");
				break;
				
			default:
				break;
		}
		//print the received message
		//plaintext[plaintext_len] = '\0';
		//printf("\n");
		//printf("3. client received_plaintext : %s\n",plaintext);	
		//printf("3. plaintext_len : %d\n",plaintext_len);
		
		printf("\n\n");
		if(plaintext[0] == 0x6c){
			memset(list_name,0x00,BUFSIZE+AES_BLOCK_LEN);
			printf("[LIST] : \n\n");
			for(j=2;j<plaintext_len;j++){
				list_name[j-2] = plaintext[j];
				//printf("%\n",list_name[j-2]); 
			}
			printf("%s\n",list_name);
			printf("\n");
		}
		if(plaintext[0] == 0x64){
			memset(filename,0x00,BUFSIZE+AES_BLOCK_LEN);
			printf("[DOWNLOAD] : \n\n");
			cnt = msg_in.cnt;
			for(j=2;j<plaintext_len;j++){
				filename[j-2] = plaintext[j];
			}

			printf("[DOWN filename] : %s\n",filename);
			//printf("filename_len : %d\n",strlen(filename));
			//printf("file : %s\n",file);
			
			FILE *fp_1 = NULL;
			fp_1 = fopen(filename,"w+");
			assert(fp_1!=NULL);
			while(cnt>0){
				//printf("1. cnt: %d\n",cnt);
				n = readn(sock, &msg_in,sizeof(APP_MSG));
				if(n==-1){
					error_handling("readn() error");
					break;
				}
				else if(n==0)
					break;
			
				msg_in.type = ntohl(msg_in.type);
				msg_in.msg_len = ntohl(msg_in.msg_len);
		
				for(i=0;i<BUFSIZE+AES_BLOCK_SIZE;i++)
				{
					plaintext[i] = 0x00;
				}	
		
				switch(msg_in.type){
					case ENCRYPTED_MSG:
						//printf("\n* encryptedMsg: \n");
						//BIO_dump_fp(stdout,(const char*)msg_in.payload,msg_in.msg_len);
						plaintext_len = decrypt(msg_in.payload,msg_in.msg_len,key,iv,(unsigned char*)plaintext);
				
						//printf("* decryptedMsg : \n");
						//BIO_dump_fp(stdout,(const char*)plaintext,plaintext_len);
							break;
					default:
							break;
				}
				//printf("2. plaintext : %s\n",plaintext);
				fwrite(plaintext,1,plaintext_len,fp_1);
				cnt--;
				if(cnt==0)
					break;
			}
			
			fclose(fp_1);
	
		}
		if(plaintext[0] == 0x75){
			printf("[UPLOAD] : \n\n");
			printf("complete upload to server\n");
		}
	}
	return NULL;
}

void list(unsigned char list_name[BUFSIZE + AES_BLOCK_LEN] )
{
	//unsigned char *filelist[20];
	int i=0,j=0;
	
	for(i=0;i<BUFSIZE+AES_BLOCK_SIZE;i++)
	{
		list_name[i] = 0x00;
	}	
	
	DIR *dir;
	struct dirent *ent;
	
	dir = opendir("./");
	if(dir!=NULL)
	{
		while((ent=readdir(dir))!=NULL){
			for(i=0;i<strlen(ent->d_name);i++){
				list_name[j+i] = ent->d_name[i];
			}
			list_name[j+i] = '/';
			j = j+i+1;

		}
		closedir(dir);
	}
	else{
		perror("");	
	}
	//plaintext[j] = "\n";
	//for(i=0;i<10;i++)
	//	printf("filename : %s \n",filelist[i]);
}

void aes_file_enc_test(char* iFilename, char oFilename[NAME_SIZE], unsigned char key[AES_KEY_128], unsigned char iv[AES_KEY_128],int *clnt_sock)
{
	FILE* ifp = NULL;		// read
	
	int clt_sock = *clnt_sock;
	int len_1;
	int n;
	int plaintext_len;
	int ciphertext_len;
	int ofilename_len;
	int file_len = 0;
	int i;
	int cnt;
	
	unsigned char plaintext[BUFSIZE+AES_BLOCK_LEN]={0x00,};
	char *pstr;
	
	APP_MSG msg_out;
	
	ofilename_len = strlen(oFilename);
	
	ifp = fopen(iFilename,"rb");
	assert(ifp!=NULL);
	
	fseek(ifp,0,SEEK_END);
	plaintext_len = ftell(ifp);		// sizeof plaintext
	fseek(ifp,0,SEEK_SET);
	
	cnt = ((plaintext_len-1) >> 10) + 1;		// /1024
	//printf("cnt : %d\n", cnt);
	
	plaintext[0] = 0x75;
	plaintext[1] = ' ';
	for(i=2;i<2+ofilename_len;i++)
	{
		plaintext[i] = oFilename[i-2];
	}
	plaintext[2+ofilename_len] = ' ';
	
	len_1 = 2+ofilename_len;
	// download & filename
	msg_out.type = ENCRYPTED_MSG;
	msg_out.type = htonl(msg_out.type);
	msg_out.cnt = cnt;
	msg_out.cnt = htonl(cnt);
	//printf("1. plaintext: %s\n",plaintext);
	//printf("1. plaintext_len :%d\n",len_1);
	ciphertext_len = encrypt((unsigned char*)plaintext, len_1, key, iv, msg_out.payload);
	msg_out.msg_len = htonl(ciphertext_len);
				
	//printf("ciphertext_len : %d\n",ciphertext_len);
	
	n = writen(clt_sock,&msg_out,sizeof(APP_MSG));
	
	// file data
	if(cnt == 1){
		memset(plaintext,0x00,sizeof(plaintext));
		fread(plaintext,plaintext_len,1,ifp);
		ciphertext_len = encrypt((unsigned char*)plaintext, plaintext_len, key, iv, msg_out.payload);
		msg_out.msg_len = htonl(ciphertext_len);
		n = writen(clt_sock,&msg_out,sizeof(APP_MSG));
	}
	else if(cnt>1)
	{
		for(i=0;i<cnt-1;i++)
		{
			memset(plaintext,0x00,sizeof(plaintext));
			fread(plaintext,1024,1,ifp);
			ciphertext_len = encrypt((unsigned char*)plaintext, 1024, key, iv, msg_out.payload);
			msg_out.msg_len = htonl(ciphertext_len);
			n = writen(clt_sock,&msg_out,sizeof(APP_MSG));
		}
		memset(plaintext,0x00,sizeof(plaintext));
		fread(plaintext,plaintext_len - (1024*(cnt-1)),1,ifp);
		ciphertext_len = encrypt((unsigned char*)plaintext, plaintext_len - (1024*(cnt-1)), key, iv, msg_out.payload);
		msg_out.msg_len = htonl(ciphertext_len);
		n = writen(clt_sock,&msg_out,sizeof(APP_MSG));
	}
	
	//printf("file_len : %d \n",file_len);
	//printf("plaintext_len : %d\n",plaintext_len);
	
}


void error_handling(char *message)
{
	fputs(message, stderr);
	fputc('\n',stderr);
	exit(1);
}
