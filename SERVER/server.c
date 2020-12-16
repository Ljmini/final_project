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


#define BUF_SIZE 100
#define MAX_CLNT 256

void *handle_clnt(void *arg);
void send_msg(char *msg, int len);
void error_handling(char *message);
void digest_message(const unsigned char*message, size_t message_len,unsigned char **digest,unsigned *digest_len);
void list(unsigned char plaintext[BUFSIZE + AES_BLOCK_LEN] );
void aes_file_enc_test(char* iFilename, char oFilename[NAME_SIZE], unsigned char key[AES_KEY_128], unsigned char iv[AES_KEY_128],int *clnt_sock);


int clnt_cnt=0;
int clnt_socks[MAX_CLNT];
pthread_mutex_t mutx;

typedef struct {
	unsigned char key[AES_KEY_128];	
	unsigned char iv[AES_KEY_128];
	int clnt_sock;
}param;

int main(int argc, char *argv[])
{
	int serv_sock;
	int clnt_sock;
	int cnt_i;
	int j;
	int id_len;
	int pw_len;
	int id_pw_len;
	
	
	struct sockaddr_in serv_addr;
	struct sockaddr_in clnt_addr;
	socklen_t clnt_addr_size;
	pthread_t t_id;
	
	param *first = (param*)malloc(sizeof(param));
	
	
	unsigned char iv[AES_KEY_128]={0x00,};
	unsigned char ID[NAME_SIZE] ={0x00,};
	unsigned char PW[PASS_SIZE] ={0x00,};	
	unsigned char ID_PW[NAME_SIZE + PASS_SIZE+2] = {0x00,};
	
	
	for(cnt_i=0;cnt_i<AES_KEY_128;cnt_i++)
	{
		iv[cnt_i] = (unsigned char)cnt_i;
	}
	// RSAES
	
	if(argc!=2){
		printf("Usage : %s <port>\n",argv[0]);
		exit(1);
	}
	
	pthread_mutex_init(&mutx,NULL);
	serv_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(serv_sock == -1)
		error_handling("socket() error");
	
	memset(&serv_addr,0,sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port=htons(atoi(argv[1]));
	
	if(bind(serv_sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1)
		error_handling("bind() error");
		
	if(listen(serv_sock,5)==-1)
		error_handling("listen() error");
		
		
	// register users ID/PW 
	printf("[FIRST] : register two users ID/PW !! \n");
	FILE *fp_1;
	fp_1 = fopen("ID_PW.txt","w");	
	if(fp_1 == NULL)
		printf("exit!!!");
	while(1)
	{
		memset(ID,0x00,NAME_SIZE);
		memset(PW,0x00,PASS_SIZE);
		memset(ID_PW,0x00,NAME_SIZE + PASS_SIZE);
		fgets(ID, NAME_SIZE,stdin); 
		
		if(strcmp(ID,"end\n") == 0)
			break;
		fgets(PW,PASS_SIZE,stdin);
		id_len =strlen(ID);
		pw_len = strlen(PW);
		//printf("ID len : %d\n",id_len);
		//printf("pw len : %d\n", pw_len);
		id_pw_len = id_len + pw_len-1;
		for(j=0;j<id_len-1;j++){
			ID_PW[j] = ID[j];
			//printf("%c",ID_PW[j]);
		}
		ID_PW[id_len-1] = '/';
		for(j=id_len;j<id_pw_len;j++)
		{
			ID_PW[j] = PW[j-(id_len)];
			//printf("%c",ID_PW[j]);
		}
		ID_PW[j] = '\n';
		//printf("%d\n",strlen(ID_PW));
		//printf("%s\n",ID_PW);
		fwrite(ID_PW,strlen(ID_PW),1,fp_1);
		//printf("done!\n");
	}
	//printf("out while\n");
	fclose(fp_1);
		


	
	while(1)
	{
		clnt_addr_size = sizeof(clnt_addr);
		clnt_sock = accept(serv_sock,(struct sockaddr*)&clnt_addr, &clnt_addr_size);
		
		if(clnt_sock == -1)
			error_handling("accept() error");
			
		pthread_mutex_lock(&mutx);
		clnt_socks[clnt_cnt++]=clnt_sock;
		pthread_mutex_unlock(&mutx);
		
		//printf("1. server clnt_cnt : %d \n",clnt_cnt);
		
		memcpy(first->iv,iv,sizeof(iv));
		first->clnt_sock = clnt_sock;
		pthread_create(&t_id,NULL,handle_clnt,(void*)first);
		pthread_detach(t_id);
		printf("\n");
		printf("[Connected client IP : %s]\n",inet_ntoa(clnt_addr.sin_addr));
	}

	close(serv_sock);
	//printf("[TCP Server] Client close : IP=%s , port=%d\n",inet_ntoa(clnt_addr.sin_addr),ntohs(clnt_addr.sin_port));
	return 0;
	
}

void *handle_clnt(void *arg)
{
	BIO *bp_public = NULL, *bp_private= NULL;
	BIO *pub = NULL;
	RSA *rsa_pubkey = NULL, *rsa_privkey = NULL;
	
	param *second = (param*)malloc(sizeof(param));
	second = arg;

	
	int clnt_sock = second->clnt_sock;
	int name_len, password_len;
	int filename1_len, filename2_len;
	
	int n = 0, i,j;
	int ciphertext_len;
	int plaintext_len;
	int encryptedkey_len;
	int publickey_len;
	int len;
	int filename_len;
	int file_len;
	int cnt;
	
	APP_MSG msg_in;	// <- client
	APP_MSG msg_out;	// -> client
	
	unsigned char key[AES_KEY_128]={0x00,};	
	unsigned char iv[AES_KEY_128]={0x00,};
	unsigned char hash[33] ={0x00,};
	unsigned char check_hash[33] = {0x00,};
	
	memcpy(iv,second->iv,sizeof(iv));
	
	unsigned char ID[NAME_SIZE] ={0x00,};
	unsigned char PW[PASS_SIZE] ={0x00,};
	unsigned char ID_PW[BUFSIZE] = {0x00,};
	
	unsigned char filename1[NAME_SIZE] = {0x00,};
	unsigned char filename2[NAME_SIZE] ={0x00,};

	char plaintext[BUFSIZE+AES_BLOCK_LEN] = {0x00,};
	char ciphertext[BUFSIZE+AES_BLOCK_LEN] = {0x00,};

	unsigned char buffer[BUF_SIZE];
	unsigned char filelist[500] = {0x00,};
	unsigned char filename[NAME_SIZE]={0x00,};
	unsigned char file[BUFSIZE+AES_BLOCK_LEN]={0x00,};
	
	unsigned char *digest = NULL;
	unsigned int digest_len;
	
	// reading public key
	bp_public = BIO_new_file("public.pem","r");
	if(!PEM_read_bio_RSAPublicKey(bp_public,&rsa_pubkey,NULL,NULL)){
		goto err;
	}

	// reading private key
	bp_private = BIO_new_file("private.pem","r");
	if(!PEM_read_bio_RSAPrivateKey(bp_private,&rsa_privkey,NULL,NULL)){
		goto err;
	}

	
	// setup process
	memset(&msg_in,0,sizeof(msg_out));
	while((n =readn(clnt_sock,&msg_in,sizeof(APP_MSG)))!=0)
	{
		//printf("n : %d\n",n);
		msg_in.type = ntohl(msg_in.type);
		msg_in.msg_len = ntohl(msg_in.msg_len);
	
		if(n==-1)
			error_handling("readn() error");
		else if(n==0)
			error_handling("reading EOF");
			
		if(msg_in.type != PUBLIC_KEY_REQUEST)
			error_handling("1. message error");
		else{
			printf("[RECEIVE PUBLIC_KEY REQUEST OK.]\n");
			// sendin PUBLIC_KEY
			memset(&msg_out,0,sizeof(msg_out));
			msg_out.type = PUBLIC_KEY;
			msg_out.type = htonl(msg_out.type);
			
			pub = BIO_new(BIO_s_mem());
			PEM_write_bio_RSAPublicKey(pub,rsa_pubkey);
			publickey_len = BIO_pending(pub);
			
			BIO_read(pub,msg_out.payload,publickey_len);
			msg_out.msg_len = htonl(publickey_len);
			
			pthread_mutex_lock(&mutx);
			n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
			pthread_mutex_unlock(&mutx);
			
			if(n==-1){
				error_handling("writen() error");
			}
			else{
				printf("[SEND PUBLIC_KEY OK.]\n");
			}
			
		}
		// receive session key
		memset(&msg_in,0,sizeof(msg_out));
		n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
		msg_in.type = ntohl(msg_in.type);
		msg_in.msg_len = ntohl(msg_in.msg_len);
		
		if(msg_in.type != ENCRYPTED_KEY){
			error_handling("2. message error");
		}
		else{
			printf("[RECEIVE ENCRYPTED SESSIONG KEY OK.]\n");
			encryptedkey_len = RSA_private_decrypt(msg_in.msg_len, msg_in.payload,buffer,rsa_privkey,RSA_PKCS1_OAEP_PADDING);
			memcpy(key,buffer,encryptedkey_len);
			/*
			for(j=0;j<encryptedkey_len;j++){
				printf("%02x ",key[j]);
			}
			*/
			//printf("success receiving encrypted_key msg\n");
		}
		
		//getchar();
		
		// ID/PW requenst
		printf("[REQUEST ID/PW (input enter)]  : ");
		if(fgets(plaintext,BUFSIZE+1,stdin)== NULL)
			exit(1);
		
		// removing '\n' character
		len = strlen(plaintext);
		if(plaintext[len-1]=='\n'){
			plaintext[len-1] = '\0';
		}
		if(strlen(plaintext)==0){
			//break;
			printf("plaintext is 0\n");
		}
		
		memset(&msg_out,0,sizeof(msg_out));
		ciphertext_len = encrypt((unsigned char*)plaintext, len, key, iv, msg_out.payload);
		msg_out.type = ID_PASSWORD;
		msg_out.type = htonl(msg_out.type);
		n = writen(clnt_sock,&msg_out,sizeof(APP_MSG));
		if(n==-1){
			error_handling("ID/pw write() error");
		}
		
		memset(&msg_in,0,sizeof(msg_in));
		n = readn(clnt_sock,&msg_in,sizeof(APP_MSG));
		
		msg_in.type = ntohl(msg_in.type);
		msg_in.msg_len = ntohl(msg_in.msg_len);
		//printf("receive msg_len : %d \n",msg_in.msg_len);
		
		if(msg_in.type == ID_PASSWORD){
			// decrypt & hash
			printf("\n");
			printf("[ID_PASSWORD] : \n");
			printf("[Enc_ID_PW_Msg ] : ");
			BIO_dump_fp(stdout,(const char*)msg_in.payload,msg_in.msg_len);
			plaintext_len = decrypt(msg_in.payload,msg_in.msg_len,key,iv,(unsigned char*)plaintext);
			printf("\n");
			printf("Dec_ID_PW_Msg ] : ");
			BIO_dump_fp(stdout,(const char*)plaintext,plaintext_len);
			printf("\n");
			// plaintext  = (ID PW HASH(pw)\0)
			//printf("server plaintext_len :%d \n",plaintext_len);
			char *arr[2] ={NULL,};
			char *ptr = strtok(plaintext," ");
			j = 0;
			while(ptr != NULL)
			{
				arr[j] = ptr;
				j++;
				if(j==2)
					break;
				ptr = strtok(NULL," ");
			}
				
			strcpy(ID,arr[0]);
			name_len = strlen(arr[0]);
			strcpy(PW,arr[1]);
			password_len = strlen(arr[1]);
			
			int hash_len = plaintext_len - (name_len + password_len + 2);
			//printf("server hash_len : %d\n", hash_len);
			for(j=0;j<hash_len;j++)
			{
				hash[j] = plaintext[j+name_len+password_len +2];
				//printf("%x ",hash[j]);
			}
			//printf("name_len : %d , password_len : %d, hash_len : %d\n\n",name_len,password_len,hash_len);
			for(j=0;j<name_len;j++)
			{
				ID_PW[j] = ID[j];
			}
			
			ID_PW[name_len] ='/';
			for(j=0;j<password_len;j++)
			{
				ID_PW[name_len+1+j] = PW[j];
			}
			ID_PW[name_len+password_len+1] = '\n';
			
			
			// [HASH]
			int count =0;
			digest_message(PW,password_len,&digest,&digest_len);
			//printf("check_hash : ");
			for(j=0;j<digest_len;j++)
			{
				//printf("%x ",digest[j]);
				if(digest[j] != hash[j])
					count++;
			}
			if(count >0){
				printf("[NO INTEGRITY! TRY AGAIN!]\n");
				goto ERR;
			}
			else{
				printf("[CHECK INTEGRITY!]\n");
			}
			
			// check in ID_PW.txt
			char buf[1024] = {0x00,};
			
			/*open file*/
			FILE *fp_1;
			fp_1 = fopen("ID_PW.txt","r");		
			int tmp =0;
			while(fgets(buf, sizeof(buf),fp_1)!= NULL)
			{
				if(strcmp(ID_PW,buf) == 0 ){
					printf("[EXIST!] \n");
					tmp = 1;
					break;
				}
				if(n == -1)
					error_handling("read() error");
				else if(n==0)
					break;	
			}
			if(tmp == 0){
				// extra 
				printf("[NOT EXIST!! YOU CAN'T ACCESS!!]\n");
				memset(plaintext,0x00,BUFSIZE+AES_BLOCK_LEN);
				strcpy(plaintext,"deny");
				
				msg_out.type = ENCRYPTED_MSG;
				msg_out.type = htonl(msg_out.type);
				
				ciphertext_len = encrypt((unsigned char*)plaintext, 4, key, iv, msg_out.payload);
				msg_out.msg_len = htonl(ciphertext_len);
				
				//printf("Server plaintext_len : %d\n", strlen(plaintext));
				//printf("server ciphertext_len : %d\n", ciphertext_len);
				n = writen(clnt_sock,&msg_out,sizeof(APP_MSG));
				//printf("////// server n : %d\n",n);
				//fwrite(ID_PW, name_len+password_len+2, 1, fp_1);
				//fclose(fp_1);
				//exit(1);
				goto ERR;
			}
			else{
				//printf("success\n");
				memset(plaintext,0x00,BUFSIZE+AES_BLOCK_LEN);
				strcpy(plaintext,"success");
				
				msg_out.type = ENCRYPTED_MSG;
				msg_out.type = htonl(msg_out.type);
				
				ciphertext_len = encrypt((unsigned char*)plaintext, 7, key, iv, msg_out.payload);
				msg_out.msg_len = htonl(ciphertext_len);
				n = writen(clnt_sock,&msg_out,sizeof(APP_MSG));
			}
			fclose(fp_1);
			//printf("[COMPLETE!]\n");
		}
		printf("[ID/PW done!]\n");
		
		// data communication with the connected client
		while(1)
		{
			printf("\n");
			//printf("now clnt_sock num : %d\n",clnt_cnt);
			printf("[waiting for read....]\n");
			// reading data from client
			n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
			
			//printf("1. received message size : %d\n",n);
			if(n==-1){
				error_handling("readn() error");
				break;
			}
			else if(n==0){	// EOF
				break;
			}
			
			msg_in.type = ntohl(msg_in.type);
			msg_in.msg_len = ntohl(msg_in.msg_len);
			msg_in.cnt = ntohl(msg_in.cnt);
			
			//printf("reset plaintext!\n");
			for(i=0;i<BUFSIZE+AES_BLOCK_SIZE;i++)
			{
				plaintext[i] = 0x00;
			}	
			
			switch(msg_in.type){
				case ENCRYPTED_MSG:
					//printf("[Enc_Msg] : ");
					//BIO_dump_fp(stdout,(const char*)msg_in.payload,msg_in.msg_len);
					plaintext_len = decrypt(msg_in.payload,msg_in.msg_len,key,iv,(unsigned char*)plaintext);
					//printf("\n");
					//printf("[Dec_Msg] : ");
					//BIO_dump_fp(stdout,(const char*)plaintext,plaintext_len);
					//printf("\n");
					break;
				default:
					break;
			}
			printf("1. server received len : %d\n",plaintext_len);
			// print the received message
			//plaintext[plaintext_len] = '\0';
			//printf("2. server recevied_plaintext : %s\n",plaintext);
			printf("\n");
			if(plaintext[0] == 0x6c){
				printf("[LIST]\n");
				list(plaintext);
				//printf("2-1. server recevied_plaintext : %s\n",plaintext);
				// removing '\n' character
				len = strlen(plaintext);
				if(plaintext[len-1]=='\n'){
					plaintext[len-1] = '\0';
				}
				if(strlen(plaintext)==0){
					printf("plaintext is 0\n");
				}
				msg_out.type = ENCRYPTED_MSG;
				msg_out.type = htonl(msg_out.type);
			
				ciphertext_len = encrypt((unsigned char*)plaintext, len, key, iv, msg_out.payload);
				msg_out.msg_len = htonl(ciphertext_len);
				
				
				
				n = writen(clnt_sock,&msg_out,sizeof(APP_MSG));
				//printf("write size : %d\n",n);
			}
			if(plaintext[0] == 0x64){
				printf("[DOWNLOAD] : \n");
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
				
				printf("[SERVER filename] : %s\n",filename1);
				printf("[CLIENT filename] : %s\n",filename2);
				
				//  open file
				//printf("clnt_sock : %d\n", clnt_sock);
				aes_file_enc_test(filename1,filename2, key, iv, &clnt_sock);
				
			}
			if(plaintext[0] == 0x75){
				printf("[UP]\n");
				cnt = msg_in.cnt;
				for(j=0;j<plaintext_len;j++)
				{
					filename[j-2] = plaintext[j];
				}
				
				printf("[DOWN filename] : %s\n",filename);
				FILE *fp_1 = NULL;
				fp_1 = fopen(filename,"w+");
				assert(fp_1!=NULL);
				while(cnt>0){
					//printf("1. cnt: %d\n",cnt);
					n = readn(clnt_sock, &msg_in,sizeof(APP_MSG));
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
		}
	}
		
ERR:	
		pthread_mutex_lock(&mutx);
		//printf("2. # of clnt_sock : %d\n",clnt_cnt);
		for(i=0;i<clnt_cnt;i++)		// remove disconnected client
		{
			if(clnt_sock==clnt_socks[i])
			{
				while(i++<clnt_cnt-1)
					clnt_socks[i]=clnt_socks[i+1];
				break;
			}
		}
		clnt_cnt--;
		pthread_mutex_unlock(&mutx);
		close(clnt_sock);
		return NULL;
		//printf("[TCP SERVER] Client close : IP = %s, port = %d\n", inet_ntoa(clnt_addr.sin_addr),ntohs(clnt_addr.sin_port));

err:
	printf("server is not ready \n");
	exit(1);
	
	return NULL;
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
	
	plaintext[0] = 0x64;
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

void list(unsigned char plaintext[BUFSIZE + AES_BLOCK_LEN] )
{
	//unsigned char *filelist[20];
	int i=0,j;
	DIR *dir;
	struct dirent *ent;
	
	memset(plaintext,0x00,BUFSIZE + AES_BLOCK_LEN);
	plaintext[0] = 0x6c;
	plaintext[1] = ' ';
	j = 2;
	
	dir = opendir("./");
	if(dir!=NULL)
	{
		while((ent=readdir(dir))!=NULL){
			for(i=0;i<strlen(ent->d_name);i++){
				plaintext[j+i] = ent->d_name[i];
			}
			plaintext[j+i] = '/';
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


void error_handling(char *message)
{
	fputs(message, stderr);
	fputc('\n',stderr);
	exit(1);
}

// EOF
