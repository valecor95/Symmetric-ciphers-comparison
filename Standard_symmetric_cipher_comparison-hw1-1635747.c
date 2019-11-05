#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <time.h>
#include <openssl/rc2.h>
#include <openssl/blowfish.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/modes.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#define DES_BLOCK_SIZE 8
#define AES_MODE 0
#define DES_MODE 1
#define BF_MODE 2
#define RC2_MODE 3

double ofb_encrypt(unsigned char * text, int length, unsigned char * key, unsigned char * iv, int mode)
{
        unsigned char * outbuf = calloc(1,length);
        double enc_time = 0;
		clock_t start, end;													// clock for timing
        
        if(mode == AES_MODE){
			int num = 0;
			unsigned char liv[16];
			memcpy(liv,iv,16);
			AES_KEY aeskey;
			AES_set_encrypt_key(key, 128, &aeskey);
			start = clock();
			AES_ofb128_encrypt(text, outbuf, length, &aeskey, liv, &num);
			end = clock();
			enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		}
		else if(mode == DES_MODE){
			int num = 0;
			DES_key_schedule des_ks;
			DES_set_key((DES_cblock *)key, &des_ks);
			unsigned char liv[8];
			memcpy(liv,iv,8);
			start = clock();
			DES_ofb64_encrypt(text, outbuf, length, &des_ks, (DES_cblock *)liv, &num);
			end = clock();
			enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		}
		else if(mode == BF_MODE){
			int num = 0;
			unsigned char liv[8];
			memcpy(liv,iv,8);
			BF_KEY bf_ks;
			BF_set_key(&bf_ks, 128, key);														
			start = clock();
			BF_ofb64_encrypt(text, outbuf, length, &bf_ks, liv, &num);
			end = clock();
			enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		}
		else if(mode == RC2_MODE){
			int num = 0;
			unsigned char liv[8];
			memcpy(liv,iv,8);
			RC2_KEY rc2_ks;
			RC2_set_key(&rc2_ks, RC2_KEY_LENGTH, key, 128);													
			start = clock();
			RC2_ofb64_encrypt(text, outbuf, length, &rc2_ks, liv, &num);
			end = clock();
			enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		}

        return enc_time;
}

double ofb_decrypt(unsigned char * enc, int length, unsigned char * key, unsigned char * iv, int mode)
{
        unsigned char * outbuf= calloc(1,length);
        double dec_time = 0;
		clock_t start, end;													// clock for timing

		if(mode == AES_MODE){
			int num = 0;
			unsigned char liv[16];
			memcpy(liv,iv,16);
			AES_KEY aeskey;
			AES_set_encrypt_key(key, 128, &aeskey);
			start = clock();
			AES_ofb128_encrypt(enc, outbuf, length, &aeskey, liv, &num);
			end = clock();
			dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		}
		else if(mode == DES_MODE){
			int num = 0;
			DES_key_schedule des_ks;
			DES_set_key((DES_cblock *)key, &des_ks);
			unsigned char liv[8];
			memcpy(liv,iv,8);
			start = clock();
			DES_ofb64_encrypt(enc, outbuf, length, &des_ks, (DES_cblock *)liv, &num);
			end = clock();
			dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		}
		else if(mode == BF_MODE){
			int num = 0;
			unsigned char liv[8];
			memcpy(liv,iv,8);
			BF_KEY bf_ks;
			BF_set_key(&bf_ks, 128, key);
			start = clock();
			BF_ofb64_encrypt(enc, outbuf, length, &bf_ks, liv, &num);
			end = clock();
			dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		}
		else if(mode == RC2_MODE){
			int num = 0;
			unsigned char liv[8];
			memcpy(liv,iv,8);
			RC2_KEY rc2_ks;
			RC2_set_key(&rc2_ks, RC2_KEY_LENGTH, key, 128);
			start = clock();
			RC2_ofb64_encrypt(enc, outbuf, length, &rc2_ks, liv, &num);
			end = clock();
			dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		}
        return dec_time;
}

int main(int argc, char **argv){
	
	if(argc < 2){
		printf("Usage: ./symmetric_cipher_comparison <filename>\n");
		return 0;
	}
	
	/*****************************************************************************************************************************/
	unsigned char* in;													// Structure for input file
	unsigned long in_size;
	// in  <-  file in input
	printf("*** READING FILE ***\n");
	
	char* filename = argv[1];
	
	int fd = open(filename, O_RDONLY, (mode_t)0666);
	int fdr = fd;
	if(fd == -1) fprintf(stderr, "Error in open file\n");
	in_size = lseek(fd, 0, SEEK_END);
	in = malloc(sizeof(char)*in_size);
	in = (char*) mmap(0, in_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fdr, 0);
	close(fdr);
	
	
	printf("Length of file = %ld Bytes\n", strlen(in));
	printf("*** END READING FILE ***\n\n");	
	/*****************************************************************************************************************************/
	
	int i=0, j=0;		
	clock_t start = 0, end = 0;													// clock for timing
	double enc_time = 0, dec_time = 0;	
	double enc_result = 0, dec_result = 0;
	unsigned char* enc_out = NULL;
	unsigned long enc_out_size = 0;
	unsigned char* dec_out = NULL;
	unsigned long dec_out_size = 0;
	unsigned char* key_128 = malloc(sizeof(char)*16);
	unsigned char* iv_128 = malloc(sizeof(char)*16);
	unsigned char* key_64 = malloc(sizeof(char)*8);
	unsigned char* iv_64 = malloc(sizeof(char)*8);
	
	
	printf("********************************************* Cipher Algorithm: AES *********************************************\n\n");
	RAND_bytes(key_128, 16);
	RAND_bytes(iv_128, 16);
	unsigned char aes_enc_iv[AES_BLOCK_SIZE] = {0};												// aux structure
	enc_out_size = ((in_size/AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;								// 16 bytes for block, adding 1 block for ensure pad
	enc_out = malloc((sizeof(char)*enc_out_size));												// Structure for encryption output
	dec_out_size = enc_out_size;
	dec_out = malloc((sizeof(char)*dec_out_size));												// Structure for decryption output
	AES_KEY* aes_ks = malloc(sizeof(AES_KEY));
	
	printf("	BLOCK size = %d bits\n", AES_BLOCK_SIZE*8);
	printf("	KEY size = 128 bits\n\n");
		
	printf("	+++++++++++++++++++++ Operative Mode: CBC\n");	
	printf("	ENCRYPTING");
	AES_set_encrypt_key(key_128, 128, aes_ks);													// Generate structure for encrypt key
	for(i = 0; i < 5; i++){	
		memcpy(aes_enc_iv, iv_128, sizeof(iv_128));
		start = clock();
		AES_cbc_encrypt(in, enc_out, enc_out_size, aes_ks, aes_enc_iv, AES_ENCRYPT);			/// ENCRYPTING
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;									// Timing		
		enc_result += enc_time;
		bzero(enc_out, enc_out_size);
	}
	printf("  Average Time ===> %lf\n", enc_result/5);
	
	printf("	DECRYPTING");
	AES_set_decrypt_key(key_128, 128, aes_ks);
	for(i = 0; i < 5; i++){	
		memcpy(aes_enc_iv, iv_128, sizeof(iv_128));
		start = clock();
		AES_cbc_encrypt(enc_out, dec_out, dec_out_size, aes_ks, aes_enc_iv, AES_DECRYPT);		/// DECRYPTING
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;									// Timing		
		dec_result += dec_time;
		bzero(dec_out, dec_out_size);
	}
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
	
	printf("	+++++++++++++++++++++ Operative Mode: ECB\n");
	printf("	ENCRYPTING");
	AES_set_encrypt_key(key_128, 128, aes_ks);
	for(i = 0, enc_result = 0; i < 5; i++){		
		start = clock();
		for(j = 0; j < in_size; j+=AES_BLOCK_SIZE){
			AES_ecb_encrypt(in+j, enc_out+j, aes_ks, AES_ENCRYPT);
		}
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
		bzero(enc_out, enc_out_size);
	}
	printf("  Average Time ===> %lf\n", enc_result/5);
	printf("	DECRYPTING");
	AES_set_decrypt_key(key_128, 128, aes_ks);
	for(i = 0, dec_result = 0; i < 5; i++){		
		start = clock();
		for(j = 0; j < enc_out_size; j+=AES_BLOCK_SIZE){
			AES_ecb_encrypt(enc_out+j, dec_out+j, aes_ks, AES_DECRYPT);
		}
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
		bzero(dec_out, dec_out_size);
	}		
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));

	printf("	+++++++++++++++++++++ Operative Mode: OFB\n");
	RAND_bytes(key_128, 16);
	RAND_bytes(iv_128, 16);
	
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){
		enc_time = ofb_encrypt(in, enc_out_size, key_128, iv_128, AES_MODE);
		enc_result += enc_time;	
	}																
	printf("  Average Time ===> %lf\n", enc_result/5);
	
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		dec_time = ofb_decrypt(enc_out, dec_out_size, key_128, iv_128, AES_MODE);
		dec_result += dec_time;
	}									
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
	
	free(enc_out);
	free(dec_out);


	printf("********************************************* Cipher Algorithm: DES *********************************************\n\n");
	enc_out_size = ((in_size/DES_BLOCK_SIZE) + 1) * DES_BLOCK_SIZE;							// 8 bytes for block, adding 1 block for ensure pad
	dec_out_size = enc_out_size;
	enc_out = malloc(sizeof(char)*enc_out_size);											// Structure for encryption output
	dec_out = malloc(sizeof(char)*dec_out_size);											// Structure for decryption output
	
	DES_cblock seed = {0,1,2,3,4,5,6,7};
	RAND_seed(seed, sizeof(DES_cblock));
	RAND_bytes(iv_64, 8);
	RAND_bytes(key_64, 8);
	DES_key_schedule* keysched = malloc(sizeof(DES_key_schedule));
	DES_cblock* ivec = malloc(sizeof(DES_cblock));
	
	printf("	BLOCK size = %d bits\n", DES_BLOCK_SIZE*8);
	printf("	KEY size = %ld bits\n\n", DES_KEY_SZ*8);	
	
	printf("	+++++++++++++++++++++ Operative Mode: CBC\n");
	DES_random_key((DES_cblock*) key_64);
	DES_set_odd_parity((DES_cblock*) key_64);
    if (DES_set_key_checked((DES_cblock *)key_64, keysched)){
        fprintf(stderr, "ERROR: Unable to set key schedule\n");
        exit(1);
    }
  
    printf("	ENCRYPTING");
    for(i = 0, enc_result=0; i < 5; i++){
		memcpy(ivec, iv_64, sizeof(iv_64));
		start = clock();
		DES_ncbc_encrypt(in, enc_out, enc_out_size, keysched, ivec, DES_ENCRYPT);
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
		bzero(enc_out, enc_out_size);
	}
	printf("  Average Time ===> %lf\n", enc_result/5);
	
	printf("	DECRYPTING");
	for(i = 0, dec_result=0; i < 5; i++){
		memcpy(ivec, iv_64, sizeof(iv_64));
		start = clock();
		DES_ncbc_encrypt(enc_out, dec_out, dec_out_size, keysched, ivec, DES_DECRYPT);
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
		bzero(dec_out, dec_out_size);
	}
	printf("  Average Time ===> %lf\n", dec_result/5);
    printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
	
    
	printf("	+++++++++++++++++++++ Operative Mode: ECB\n");
	
	DES_set_key((DES_cblock *)key_64, keysched);	
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){
		start = clock();
		for(j = 0; j < enc_out_size; j+=DES_BLOCK_SIZE){
			DES_ecb_encrypt((DES_cblock *)(in+j),(DES_cblock *)(enc_out+j), keysched, DES_ENCRYPT);
		}
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
		bzero(enc_out, enc_out_size);
	}
	printf(" Average Time ===> %lf\n", enc_result/5);
	
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		start = clock();
		for(j = 0; j < dec_out_size; j+=DES_BLOCK_SIZE){
			DES_ecb_encrypt((DES_cblock *)(enc_out+j),(DES_cblock *)(dec_out+j), keysched, DES_DECRYPT);
		}
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
		bzero(dec_out, dec_out_size);
	}
    printf(" Average Time ===> %lf\n", dec_result/5); 
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
	
	printf("	+++++++++++++++++++++ Operative Mode: OFB\n");
	

	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){
		enc_time = ofb_encrypt(in, enc_out_size, key_64, iv_64, DES_MODE);
		enc_result += enc_time;	
	}																
	printf("  Average Time ===> %lf\n", enc_result/5);
	
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		dec_time = ofb_decrypt(enc_out, dec_out_size, key_64, iv_64, DES_MODE);
		dec_result += dec_time;
	}									
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));

	free(enc_out);
	free(dec_out);


	printf("********************************************* Cipher Algorithm: BLOWFISH *********************************************\n\n");
	RAND_bytes(key_128, 16);
	RAND_bytes(iv_64, 8);
	unsigned char bf_enc_iv[BF_BLOCK];
	enc_out_size = ((in_size/BF_BLOCK) + 1) * BF_BLOCK;										// 8 bytes for block, adding 1 block for ensure pad
	dec_out_size = enc_out_size;
	enc_out = malloc(sizeof(char)*enc_out_size);										
	dec_out = malloc(sizeof(char)*dec_out_size);											
	
	BF_KEY bf_ks;
	BF_set_key(&bf_ks, 128, key_128);														
	
	printf("	BLOCK size = %d bits\n", BF_BLOCK*8);
	printf("	KEY size = 128 bits\n\n");	
	
	printf("	+++++++++++++++++++++ Operative Mode: CBC\n");
	printf("	ENCRYPTING");									
	for(i = 0, enc_result = 0; i < 5; i++){
		memcpy(bf_enc_iv, iv_64, sizeof(iv_64));						
		start = clock();
		BF_cbc_encrypt(in, enc_out, enc_out_size, &bf_ks, bf_enc_iv, BF_ENCRYPT);					
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
		bzero(enc_out, enc_out_size);
	}
    printf(" Average Time ===> %lf\n", enc_result/5);
	
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		memcpy(bf_enc_iv, iv_64, sizeof(iv_64));	
		start = clock();
		BF_cbc_encrypt(enc_out, dec_out, dec_out_size, &bf_ks, bf_enc_iv, BF_DECRYPT);				
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
		bzero(dec_out, dec_out_size);
    }    								
    printf(" Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
	
	 
	printf("	+++++++++++++++++++++ Operative Mode: ECB\n"); 
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){
		start = clock();
		for(j = 0; j < enc_out_size; j+=8){
			BF_ecb_encrypt(in+j, enc_out+j, &bf_ks, BF_ENCRYPT);
		}
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
		bzero(enc_out, enc_out_size);
	}
	printf(" Average Time ===> %lf\n", enc_result/5);
	
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		start = clock();
		for(j = 0; j < dec_out_size; j+=8){
			BF_ecb_encrypt(enc_out+j, dec_out+j, &bf_ks, BF_DECRYPT);
		}
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
		bzero(dec_out, dec_out_size);
	}
	
    printf(" Average Time ===> %lf\n", dec_result/5); 
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5)); 
	
	printf("	+++++++++++++++++++++ Operative Mode: OFB\n");
	
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){
		enc_time = ofb_encrypt(in, enc_out_size, key_128, iv_64, BF_MODE);
		enc_result += enc_time;	
	}																
	printf("  Average Time ===> %lf\n", enc_result/5);
	
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		dec_time = ofb_decrypt(enc_out, dec_out_size, key_128, iv_64, BF_MODE);
		dec_result += dec_time;
	}									
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));

	free(enc_out);
	free(dec_out);

	printf("********************************************* Cipher Algorithm: RC2 *********************************************\n\n");
	RAND_bytes(key_128, 16);
	RAND_bytes(iv_64, 8);
	unsigned char rc2_enc_iv[RC2_BLOCK];
	enc_out_size = ((in_size/RC2_BLOCK) + 1) * RC2_BLOCK;											// 8 bytes for block, adding 1 block for ensure pad
	dec_out_size = enc_out_size;
	enc_out = malloc(sizeof(char)*enc_out_size);										
	dec_out = malloc(sizeof(char)*dec_out_size);											
	
	RC2_KEY rc2_ks;
	RC2_set_key(&rc2_ks, RC2_KEY_LENGTH, key_128, 128);			
	
	printf("	BLOCK size = %d bits\n", RC2_BLOCK*8);
	printf("	KEY size = %d bits\n\n", RC2_KEY_LENGTH*8);											
	
	printf("	+++++++++++++++++++++ Operative Mode: CBC\n");
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){ 									
		memcpy(rc2_enc_iv, iv_64, sizeof(iv_64));						
		start = clock();
		RC2_cbc_encrypt(in, enc_out, enc_out_size, &rc2_ks, rc2_enc_iv, RC2_ENCRYPT);					
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;	
		bzero(enc_out, enc_out_size);	
	}
    printf(" Average Time ===> %lf\n", enc_result/5);
	
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){ 
		memcpy(rc2_enc_iv, iv_64, sizeof(iv_64));
		start = clock();
		RC2_cbc_encrypt(enc_out, dec_out, dec_out_size, &rc2_ks, rc2_enc_iv, RC2_DECRYPT);				
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;	
		dec_result += dec_time;	
		bzero(dec_out, dec_out_size);
	}							
    printf(" Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));							
	 
	printf("	+++++++++++++++++++++ Operative Mode: ECB\n"); 
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){ 
		start = clock();
		for(j = 0; j < enc_out_size; j+=8){
			RC2_ecb_encrypt(in+j, enc_out+j, &rc2_ks, RC2_ENCRYPT);
		}
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
		bzero(enc_out, enc_out_size);
	}
	printf(" Average Time ===> %lf\n", enc_result/5);
	
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		start = clock();
		for(j = 0; j < dec_out_size; j+=8){
			RC2_ecb_encrypt(enc_out+j, dec_out+j, &rc2_ks, RC2_DECRYPT);
		}
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
		bzero(dec_out, dec_out_size);
	}
    printf(" Average Time ===> %lf\n", dec_result/5); 
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5)); 
	
	printf("	+++++++++++++++++++++ Operative Mode: OFB\n");
	
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){
		enc_time = ofb_encrypt(in, enc_out_size, key_128, iv_64, RC2_MODE);
		enc_result += enc_time;	
	}																
	printf("  Average Time ===> %lf\n", enc_result/5);
	
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		dec_time = ofb_decrypt(enc_out, dec_out_size, key_128, iv_64, RC2_MODE);
		dec_result += dec_time;
	}									
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
	
	free(enc_out);
	free(dec_out);
	free(key_128);
	free(key_64);
	free(iv_128);
	free(iv_64);
	
	return 0;
}
