#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <openssl/des.h>
#include <openssl/rand.h>

#define BLOCK 8
#define BUFSIZE 64
#define NAMELEN 256

void revuchararr(unsigned char a[8]){
	if(a != NULL){
		int low = 0;
		int high = 7;
		while(low < high){
			unsigned char temp = a[low];
			a[low] = a[high];
			a[high] = temp;
			low++;
			high--;
		}
	}
}

void num2uchararray(long unsigned int v, unsigned char a[8]){
	int x = v;
	int it = 0;
	while(x>0 && it<8){
		int temp = x%256;
		a[it] = temp;
		x /= 256;
		it++;
	}
	revuchararr(a);
}

int isequaluchararray(unsigned char a[], unsigned char b[], int size){
	int i;
	for(i=0;i<size;i++){
		if(a[i] != b[i]){
			return 0;
		}
	}
	return 1;
}

unsigned long int uchararray2lu(unsigned char a[], int size){
	unsigned long int ans = 0;;
	unsigned int base = 256;
	int i;
	for(i=0;i<size;i++){
		unsigned long int adjbase = 1;
		int j;
		for(j=0;j<size-i-1;j++){
			adjbase *= base;
		}
		ans += adjbase * a[i];
	}
	return ans;
}
int main(int argc, char *argv[]){
	if(argc != 5){
		printf("Usage:%s <plaintext_file> <ciphertext_file <key_start> <iterations>\n",argv[0]);
		return 1;
	}

	int i;
	unsigned char plainbuff[BLOCK],cipherbuff[BLOCK],check[BLOCK];
	DES_cblock key; //the cblock key
	DES_key_schedule keysched; //for key scheduling

	memset(plainbuff, 0, sizeof(*plainbuff)); //zero the buffers
	memset(cipherbuff, 0, sizeof(*cipherbuff));
	memset(check, 0, sizeof(*check));

	int plaintextfd,ciphertextfd;//,wfd; //read and write file descriptors
	if((plaintextfd = open(argv[1],O_RDONLY)) == -1){
		perror("open error for input file\n");
	}
	if((ciphertextfd = open(argv[2],O_RDONLY)) == -1){
		perror("open error for input file\n");
	}

	int plainbytesread = read(plaintextfd,plainbuff,BLOCK); //read 8 bytes
	if(plainbytesread != BLOCK){ //didn't read 8 bytes
		if(plainbytesread == -1){
			printf("error:%s\n",strerror(errno));
		}else{
			printf("could not read 8 bytes\n");
		}
		return 1;
	}
	int cipherbytesread = read(ciphertextfd,cipherbuff,BLOCK); //read 8 bytes
	if(cipherbytesread != BLOCK){ //didn't read 8 bytes
		if(cipherbytesread == -1){
			printf("error:%s\n",strerror(errno));
		}else{
			printf("could not read 8 bytes\n");
		}
		return 1;
	}

	//printf("plain|cipher\n");
	for(i=0;i<8;i++){
		//printf("%03u|%03u\n",plainbuff[i],cipherbuff[i]);
	}
	//printf("\n");

	unsigned long int start = atol(argv[3]);
	unsigned long int iterations = atol(argv[4]);
	unsigned long int j;

	unsigned char randkey[8];
	memset(randkey,0,sizeof(*randkey)*8);

	unsigned long int value = -1;
	for(j=0;j<iterations;j++){
		memset(randkey,0,sizeof(*randkey)*8);
		num2uchararray(start+j,randkey); //turn number into actual key
		for(i=0;i<8;i++){ //copy the number into the key.
			key[i] = randkey[i]; //put values in the key structure
		}
		DES_set_odd_parity(&key); //set odd parity on key
		DES_set_key((C_Block *)key, &keysched); //expand the key for speed
		DES_ecb_encrypt((C_Block *)cipherbuff,(C_Block *)check, &keysched, DES_DECRYPT); //decrypt the block with the current key being checked
		if(isequaluchararray(plainbuff,check,BLOCK)){
			//printf("key is %lu adjusted with odd parity\n",start+j);
			value = start+j;
			printf("randkey|key = %lu (with odd parity)\n",start+j);
			for(i=0;i<8;i++){
				printf("%03u|%03u\n",randkey[i],key[i]);
			}
			printf("\n");
			break;
		}
	}

	if(value != -1){
		printf("Key Found!\n");
		printf("key without parity = %lu\n",value);
		printf("true key = %lu\n",uchararray2lu(key,BLOCK));
		for(i=0;i<8;i++){
			printf("[%03u]",key[i]);
		}
		printf("\n");
	}else{
		printf("Key not found in closed interval [%lu,%lu]\n",start,start+iterations-1);
	}

	close(plaintextfd); //close the files
	close(ciphertextfd);
	//close(wfd);

	return 0;
}
