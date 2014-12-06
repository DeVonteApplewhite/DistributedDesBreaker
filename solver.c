#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
//#include <time.h> //for timing purposes
#include <limits.h>
#include <openssl/des.h>
#include <openssl/rand.h>

#define BLOCK 8 //size in bytes of the plaintext and ciphertext

//reverses an array to get true converted number value
void revuchararr(unsigned char a[8]){
	if(a != NULL){ //ensure the array is valid
		int low = 0; //start at one end
		int high = 7; //end at the other end
		while(low < high){ //do while not converging in the middle
			unsigned char temp = a[low]; //swapping values
			a[low] = a[high];
			a[high] = temp;
			low++; //increase start
			high--; //decrease end
		}
	}
}

//convert a number into an unsigned char array
void num2uchararray(long unsigned int v, unsigned char a[8]){
	int x = v; //get value to work with
	int it = 7; //iterator for placing into the array
	while(x>0 && it>=0){ //while not at max array index and x is nonzero
		int temp = x%256; //get first 256 remainder
		a[it] = temp; //store it
		x /= 256; //make x smaller by a factor of 256
		it--; //advance iterator
	}
	int i;
	for(i=it;i>=0;i--){
		a[i] = 0; //zero rest of array
	}	
}

//checks if two unsigned char arrays are equal
int isequaluchararray(unsigned char a[], unsigned char b[], int size){
	int i;
	for(i=0;i<size;i++){
		if(a[i] != b[i]){ //return false if any part is not equal
			return 0;
		}
	}
	return 1; //else return true
}

//convert a unsigned char array into an unsigned long
unsigned long int uchararray2lu(unsigned char a[], int size){
	unsigned long int ans = 0; //set up answer
	unsigned int base = 256; //unsigned char is 8 bytes so use base 256
	int i;
	for(i=0;i<size;i++){
		unsigned long int adjbase = 1; //adjusted base for iteration 
		int j;
		for(j=0;j<size-i-1;j++){
			adjbase *= base; //scale adjbase up to 256^(i-1)
		}
		ans += adjbase * a[i]; //update answer based on a[i]'s value
	}
	return ans;
}

int main(int argc, char *argv[]){
	if(argc != 5){ //check for all arguments
		printf("Usage:%s <plaintext_file> <ciphertext_file <key_start> <iterations>\n",argv[0]);
		return 1; //exit failure
	}

	int i;
	//buffers for plaintext, ciphertext, and the equality check
	unsigned char plainbuff[BLOCK],cipherbuff[BLOCK],check[BLOCK];
	DES_cblock key; //the cblock key
	DES_key_schedule keysched; //for key scheduling

	memset(plainbuff, 0, sizeof(*plainbuff)); //zero the buffers
	memset(cipherbuff, 0, sizeof(*cipherbuff));
	memset(check, 0, sizeof(*check));

	int plaintextfd,ciphertextfd; //read and write file descriptors
	if((plaintextfd = open(argv[1],O_RDONLY)) == -1){ //failed to open
		perror("open error for input file\n");
	}
	if((ciphertextfd = open(argv[2],O_RDONLY)) == -1){ //failed to open
		perror("open error for input file\n");
	}

	int plainbytesread = read(plaintextfd,plainbuff,BLOCK); //read 8 bytes
	if(plainbytesread != BLOCK){ //didn't read 8 bytes
		if(plainbytesread == -1){ //specific error that errno reports
			printf("error:%s\n",strerror(errno));
		}else{
			printf("could not read 8 bytes\n"); //regular error
		}
		return 1; //exit failure
	}

	int cipherbytesread = read(ciphertextfd,cipherbuff,BLOCK); //read 8 bytes
	if(cipherbytesread != BLOCK){ //didn't read 8 bytes
		if(cipherbytesread == -1){ //specific error that errno reports
			printf("error:%s\n",strerror(errno));
		}else{
			printf("could not read 8 bytes\n"); //regular error
		}
		return 1; //exit failure
	}

	unsigned long int start = atol(argv[3]); //get starting value
	unsigned long int iterations = atol(argv[4]); //get number of iterations
	unsigned long int j;

	//unsigned char randkey[8]; //random key to work with
	//memset(randkey,0,sizeof(*randkey)*8); //zero the random key

	unsigned long int value = -1; //the correct key
	for(j=0;j<iterations;j++){
		//memset(randkey,0,sizeof(*randkey)*8); //zero random key
		num2uchararray(start+j,key); //turn number into actual key
		//for(i=0;i<8;i++){ //copy the number into the key.
		//	key[i] = randkey[i]; //put values in the key structure
		//}
		DES_set_odd_parity(&key); //set odd parity on key
		DES_set_key((C_Block *)key, &keysched); //expand the key for speed
		DES_ecb_encrypt((C_Block *)cipherbuff,(C_Block *)check, &keysched, DES_DECRYPT); //decrypt the block with the current key being checked
		if(isequaluchararray(plainbuff,check,BLOCK)){ //checking equality
			value = start+j;
			//printf("randkey|key = %lu (with odd parity)\n",start+j);
			//for(i=0;i<8;i++){
			//	printf("%03u|%03u\n",randkey[i],key[i]); //printing bytes
			//}
			//printf("\n");
			break; //found key so exit early
		}
	}

	if(value != -1){ //key not found
		printf("1,");
		printf("%lu,",value);
		printf("%lu,",uchararray2lu(key,BLOCK));
		for(i=0;i<8;i++){ //print the key out
			printf("[%03u]",key[i]);
		}
		printf("\n");
	}else{
		printf("0,%lu,%lu,null\n",start,start+iterations-1);
	}

	close(plaintextfd); //close the files
	close(ciphertextfd);

	return 0;
}
