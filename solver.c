#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <limits.h>
#include <openssl/des.h>
#include <openssl/rand.h>

#define BLOCK 8 //size in bytes of the plaintext and ciphertext

struct targs{
	unsigned int tnum;
	unsigned long int start;
	unsigned long int iterations;
};

unsigned char plainbuff[8][BLOCK],cipherbuff[8][BLOCK];//,check[BLOCK];

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
void num2uchararray(unsigned long int v, unsigned char a[8]){
	unsigned long int x = v; //get value to work with
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
	unsigned long int base = 256; //uchar is 8 bytes so use base 256
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

void * find_key(struct targs *args)
{
	unsigned char check[BLOCK]; //for checking the answer
	DES_cblock key; //the cblock key
	DES_key_schedule keysched; //for key scheduling

	memset(check, 0, sizeof(*check)*BLOCK);

	unsigned long int start = args->start; //get starting value
	unsigned long int iterations = args->iterations; //number of iterations
	unsigned int i = args->tnum;
	unsigned long int j;

	for(j=0;j<iterations;j++){
		num2uchararray(start+j,key); //turn number into actual key
		DES_set_odd_parity(&key); //set odd parity on key
		DES_set_key((C_Block *)key, &keysched); //expand the key for speed
		DES_ecb_encrypt((C_Block *)cipherbuff[i],(C_Block *)check, &keysched, DES_DECRYPT); //decrypt the block with the current key being checked
		if(isequaluchararray(plainbuff[i],check,BLOCK)){ //checking equality
			unsigned char *ans = malloc(sizeof(unsigned char)*BLOCK);
			memcpy(ans,key,BLOCK); //copy over answer
			return ans; //return answer
		}
	}

	return NULL; //answer not found
}

int main(int argc, char *argv[]){
	if(argc != 6){ //check for all arguments
		printf("Usage:%s <plaintext_file> <ciphertext_file <key_start> <iterations> <nthreads>\n",argv[0]);
		return 1; //exit failure
	}

	unsigned int i;

	memset(plainbuff, 0, sizeof(*plainbuff)); //zero the buffers
	memset(cipherbuff, 0, sizeof(*cipherbuff));

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

	for(i=1;i<8;i++){ //copy all info from 0th buffer to 7th buffer
		memcpy(plainbuff[i],plainbuff[0],BLOCK);
		memcpy(cipherbuff[i],cipherbuff[0],BLOCK);
	}

	unsigned long int start = atol(argv[3]); //get starting value
	unsigned long int iterations = atol(argv[4]); //get number of iterations
	unsigned int nthreads = atoi(argv[5]); //get number of threads

	struct targs *allargs = malloc(sizeof(struct targs)*nthreads);
	pthread_t *threads = malloc(sizeof(pthread_t)*nthreads); //malloc threads

	unsigned long int div;
	int dodiff = 0;
	if(iterations%nthreads == 0){ //perfect divide
		div = iterations/nthreads;
	}else{
		div = iterations/nthreads + 1; //account for the extra slack
		dodiff = 1;
	}

	for(i=0;i<nthreads;i++){ //set up arguments and dispatch threads
		allargs[i].tnum = i; //thread number
		allargs[i].start = start+div*i; //set up starting point
		if(i != nthreads-1){ //not ending thread
			allargs[i].iterations = div;
		}else{
			if(dodiff){
				allargs[i].iterations = iterations%div; //ending work
			}else{
				allargs[i].iterations = div; //ending work
			}
		}

		int st;
		//keep dispatching a particular thread until it actually succeeds
		while((st=pthread_create(&threads[i],NULL,(void *)&find_key,&allargs[i]))!=0){
			//printf("Thread failed to create: %s\n",strerror(errno));
		}
	}

	unsigned long int value = -1; //the correct key
	unsigned char *foundkey;
	for(i=0;i<nthreads;i++){ //wait for the threads to join
		int rt = pthread_join(threads[i],(void **)&foundkey); //wait for threads to finish
		if(rt == 0){
			if(foundkey != NULL){ //a solution is found
				value = uchararray2lu(foundkey,BLOCK);
				break; //get out of loop
			}
		}
	}

	if(value != -1){ //key not found
		printf("1,");
		printf("%lu,",value);
		printf("%lu,",uchararray2lu(foundkey,BLOCK));
		for(i=0;i<8;i++){ //print the key out
			printf("[%03u]",foundkey[i]);
		}
		printf("\n");
	}else{
		printf("0,%lu,%lu,null\n",start,start+iterations-1);
	}

	free(foundkey); //free the key
	free(threads);
	free(allargs);
	close(plaintextfd); //close the files
	close(ciphertextfd);

	return 0;
}
