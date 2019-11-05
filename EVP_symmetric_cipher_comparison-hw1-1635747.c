#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <time.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/rc2.h>
#include <openssl/modes.h>

#define CBC 0
#define ECB 1
#define OFB 2

#define AES 0
#define DES 1
#define BF 2
#define RC2 3

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext, int mode, int cipher)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     */
    if(cipher == AES){
		if(mode == CBC){
			if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
				handleErrors();
		}
		if(mode == ECB){
			if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
				handleErrors();
		}
		if(mode == OFB){
			if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key, iv))
				handleErrors();
		}
	}
	if(cipher == DES){
		if(mode == CBC){
			if(1 != EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv))
				handleErrors();
		}
		if(mode == ECB){
			if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, key, iv))
				handleErrors();
		}
		if(mode == OFB){
			if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ofb(), NULL, key, iv))
				handleErrors();
		}
	}
	if(cipher == BF){
		if(mode == CBC){
			if(1 != EVP_EncryptInit_ex(ctx, EVP_bf_cbc(), NULL, key, iv))
				handleErrors();
		}
		if(mode == ECB){
			if(1 != EVP_EncryptInit_ex(ctx, EVP_bf_ecb(), NULL, key, iv))
				handleErrors();
		}
		if(mode == OFB){
			if(1 != EVP_EncryptInit_ex(ctx, EVP_bf_ofb(), NULL, key, iv))
				handleErrors();
		}
	}
	if(cipher == RC2){
		if(mode == CBC){
			if(1 != EVP_EncryptInit_ex(ctx, EVP_rc2_cbc(), NULL, key, iv))
				handleErrors();
		}
		if(mode == ECB){
			if(1 != EVP_EncryptInit_ex(ctx, EVP_rc2_ecb(), NULL, key, iv))
				handleErrors();
		}
		if(mode == OFB){
			if(1 != EVP_EncryptInit_ex(ctx, EVP_rc2_ofb(), NULL, key, iv))
				handleErrors();
		}
	}
    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

void decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, int mode, int cipher)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     */
    if(cipher == AES){
		if(mode == CBC){
			if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
				handleErrors();
		}
		if(mode == ECB){
			if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
				handleErrors();
		}
		if(mode == OFB){
			if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key, iv))
				handleErrors();
		}
	}
	if(cipher == DES){
		if(mode == CBC){
			if(1 != EVP_DecryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv))
				handleErrors();
		}
		if(mode == ECB){
			if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ecb(), NULL, key, iv))
				handleErrors();
		}
		if(mode == OFB){
			if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ofb(), NULL, key, iv))
				handleErrors();
		}
	}
	if(cipher == BF){
		if(mode == CBC){
			if(1 != EVP_DecryptInit_ex(ctx, EVP_bf_cbc(), NULL, key, iv))
				handleErrors();
		}
		if(mode == ECB){
			if(1 != EVP_DecryptInit_ex(ctx, EVP_bf_ecb(), NULL, key, iv))
				handleErrors();
		}
		if(mode == OFB){
			if(1 != EVP_DecryptInit_ex(ctx, EVP_bf_ofb(), NULL, key, iv))
				handleErrors();
		}
	}
	if(cipher == RC2){
		if(mode == CBC){
			if(1 != EVP_DecryptInit_ex(ctx, EVP_rc2_cbc(), NULL, key, iv))
				handleErrors();
		}
		if(mode == ECB){
			if(1 != EVP_DecryptInit_ex(ctx, EVP_rc2_ecb(), NULL, key, iv))
				handleErrors();
		}
		if(mode == OFB){
			if(1 != EVP_DecryptInit_ex(ctx, EVP_rc2_ofb(), NULL, key, iv))
				handleErrors();
		}
	}
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}


int main (int argc, char **argv)
{
	
	/* Message to be encrypted */
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
	unsigned char* key_256 = malloc(sizeof(char)*32);
	unsigned char* key_64 = malloc(sizeof(char)*8);
	unsigned char* iv_128 = malloc(sizeof(char)*16);
	unsigned char* iv_64 = malloc(sizeof(char)*8);
	unsigned char* aux_iv_128 = malloc(sizeof(char)*16);
	unsigned char* aux_iv_64 = malloc(sizeof(char)*8);
	clock_t start, end;																				// clock for timing
	double enc_time = 0, dec_time = 0, enc_result = 0, dec_result = 0;
	int i = 0;
	
	
	printf("********************************************* Cipher Algorithm: AES *********************************************\n\n");
	RAND_bytes(key_128, 16);
	RAND_bytes(iv_128, 16);
	int enc_out_size = ((in_size/AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;								// 16 bytes for block, adding 1 block for ensure pad
	unsigned char* enc_out = malloc((sizeof(char)*enc_out_size));									// Structure for encryption output
	int dec_out_size = enc_out_size;
	unsigned char* dec_out = malloc((sizeof(char)*dec_out_size));									// Structure for decryption output
	
	
    printf("	+++++++++++++++++++++ Operative Mode: CBC\n");
	printf("	ENCRYPTING");
	memcpy(aux_iv_128, iv_128, sizeof(iv_128));
	start = clock();
	encrypt(in, in_size, key_128, aux_iv_128, enc_out, CBC, AES);
	end = clock();
	enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", enc_time);
    
	printf("	DECRYPTING");
	memcpy(aux_iv_128, iv_128, sizeof(iv_128));
	start = clock();
	decrypt(enc_out, enc_out_size, key_128, aux_iv_128, dec_out, CBC, AES);
	end = clock();
	dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", dec_time);
	printf("	SPEED RATIO ==========> %lf\n\n", (enc_time/dec_time));
		
	bzero(enc_out, enc_out_size);
	bzero(dec_out, dec_out_size);
	
	printf("	+++++++++++++++++++++ Operative Mode: ECB\n");
	printf("	ENCRYPTING");
	memcpy(aux_iv_128, iv_128, sizeof(iv_128));
	start = clock();
	encrypt(in, in_size, key_128, iv_128, enc_out, ECB, AES);
	end = clock();
	enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", enc_time);
    
	printf("	DECRYPTING");
	memcpy(aux_iv_128, iv_128, sizeof(iv_128));
	start = clock();
	decrypt(enc_out, enc_out_size, key_128, iv_128, dec_out, ECB, AES);
	end = clock();
	dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", dec_time);
	printf("	SPEED RATIO ==========> %lf\n\n", (enc_time/dec_time));
		
	bzero(enc_out, enc_out_size);
	bzero(dec_out, dec_out_size);
	
	printf("	+++++++++++++++++++++ Operative Mode: OFB\n");
	printf("	ENCRYPTING");
	memcpy(aux_iv_128, iv_128, sizeof(iv_128));
	start = clock();
	encrypt(in, in_size, key_128, aux_iv_128, enc_out, OFB, AES);
	end = clock();
	enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", enc_time);
    
	printf("	DECRYPTING");
	memcpy(aux_iv_128, iv_128, sizeof(iv_128));
	start = clock();
	decrypt(enc_out, enc_out_size, key_128, aux_iv_128, dec_out, OFB, AES);
	end = clock();
	dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", dec_time);
	printf("	SPEED RATIO ==========> %lf\n\n", enc_time/dec_time);
	
	
	free(enc_out);
	free(dec_out);
	
	printf("********************************************* Cipher Algorithm: DES *********************************************\n\n");
	RAND_bytes(key_64, 8);
	RAND_bytes(iv_64, 8);
	enc_out_size = ((in_size/8) + 1) * 8;														
	enc_out = malloc((sizeof(char)*enc_out_size));									
	dec_out_size = enc_out_size;
	dec_out = malloc((sizeof(char)*dec_out_size));									
	
	
    printf("	+++++++++++++++++++++ Operative Mode: CBC\n");
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){														// Trie encryption and dec 5 times
		memcpy(aux_iv_64, iv_64, sizeof(iv_64));
		start = clock();
		encrypt(in, in_size, key_64, aux_iv_64, enc_out, CBC, DES);
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
	}
	printf("  Average Time ===> %lf\n", enc_result/5);
    
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		memcpy(aux_iv_64, iv_64, sizeof(iv_64));
		start = clock();
		decrypt(enc_out, enc_out_size, key_64, aux_iv_64, dec_out, CBC, DES);
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
	}
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
	
	bzero(enc_out, enc_out_size);
	bzero(dec_out, dec_out_size);
	
	printf("	+++++++++++++++++++++ Operative Mode: ECB\n");
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){
		start = clock();
		encrypt(in, in_size, key_64, iv_64, enc_out, ECB, DES);
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
	}
	printf("  Average Time ===> %lf\n", enc_result/5);
    
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		start = clock();
		decrypt(enc_out, enc_out_size, key_64, iv_64, dec_out, ECB, DES);
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
	}
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
	
	bzero(enc_out, enc_out_size);
	bzero(dec_out, dec_out_size);
	
	printf("	+++++++++++++++++++++ Operative Mode: OFB\n");
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){
		memcpy(aux_iv_64, iv_64, sizeof(iv_64));
		start = clock();
		encrypt(in, in_size, key_64, aux_iv_64, enc_out, OFB, DES);
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
	}
	printf("  Average Time ===> %lf\n", enc_result/5);
    
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		memcpy(aux_iv_64, iv_64, sizeof(iv_64));
		start = clock();
		decrypt(enc_out, enc_out_size, key_64, aux_iv_64, dec_out, OFB, DES);
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
	}
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
	
	free(enc_out);
	free(dec_out);
	
	
	printf("********************************************* Cipher Algorithm: BLOWFISH *********************************************\n\n");
	RAND_bytes(key_128, 16);
	RAND_bytes(iv_64, 8);
	enc_out_size = ((in_size/BF_BLOCK) + 1) * BF_BLOCK;								
	enc_out = malloc((sizeof(char)*enc_out_size));									
	dec_out_size = enc_out_size;
	dec_out = malloc((sizeof(char)*dec_out_size));									
	
	
    printf("	+++++++++++++++++++++ Operative Mode: CBC\n");
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){
		memcpy(aux_iv_64, iv_64, sizeof(iv_64));
		start = clock();
		encrypt(in, in_size, key_128, aux_iv_64, enc_out, CBC, BF);
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
	}
	printf("  Average Time ===> %lf\n", enc_result/5);
    
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		memcpy(aux_iv_64, iv_64, sizeof(iv_64));
		start = clock();
		decrypt(enc_out, enc_out_size, key_128, aux_iv_64, dec_out, CBC, BF);
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
	}
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
	
	bzero(enc_out, enc_out_size);
	bzero(dec_out, dec_out_size);
	
	printf("	+++++++++++++++++++++ Operative Mode: ECB\n");
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){
		start = clock();
		encrypt(in, in_size, key_128, iv_64, enc_out, ECB, BF);
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
	}
	printf("  Average Time ===> %lf\n", enc_result/5);
    
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		start = clock();
		decrypt(enc_out, enc_out_size, key_128, iv_64, dec_out, ECB, BF);
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
	}
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
		
	bzero(enc_out, enc_out_size);
	bzero(dec_out, dec_out_size);
	
	printf("	+++++++++++++++++++++ Operative Mode: OFB\n");
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){
		memcpy(aux_iv_64, iv_64, sizeof(iv_64));
		start = clock();
		encrypt(in, in_size, key_128, aux_iv_64, enc_out, OFB, BF);
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
	}
	printf("  Average Time ===> %lf\n", enc_result/5);
    
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		memcpy(aux_iv_64, iv_64, sizeof(iv_64));
		start = clock();
		decrypt(enc_out, enc_out_size, key_128, aux_iv_64, dec_out, OFB, BF);
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
	}
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
	
	free(enc_out);
	free(dec_out);
	
	
	printf("********************************************* Cipher Algorithm: RC2 *********************************************\n\n");
	RAND_bytes(key_128, 16);
	RAND_bytes(iv_64, 8);
	enc_out_size = ((in_size/RC2_BLOCK) + 1) * RC2_BLOCK;								// 16 bytes for block, adding 1 block for ensure pad
	enc_out = malloc((sizeof(char)*enc_out_size));									// Structure for encryption output
	dec_out_size = enc_out_size;
	dec_out = malloc((sizeof(char)*dec_out_size));									// Structure for decryption output
	
	
    printf("	+++++++++++++++++++++ Operative Mode: CBC\n");
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){
		memcpy(aux_iv_64, iv_64, sizeof(iv_64));
		start = clock();
		encrypt(in, in_size, key_128, aux_iv_64, enc_out, CBC, RC2);
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
	}
	printf("  Average Time ===> %lf\n", enc_result/5);
    
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		memcpy(aux_iv_64, iv_64, sizeof(iv_64));
		start = clock();
		decrypt(enc_out, enc_out_size, key_128, aux_iv_64, dec_out, CBC, RC2);
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
	}
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
	
	bzero(enc_out, enc_out_size);
	bzero(dec_out, dec_out_size);
	
	printf("	+++++++++++++++++++++ Operative Mode: ECB\n");
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){
		start = clock();
		encrypt(in, in_size, key_128, iv_64, enc_out, ECB, RC2);
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
	}
	printf("  Average Time ===> %lf\n", enc_result/5);
    
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		start = clock();
		decrypt(enc_out, enc_out_size, key_128, iv_64, dec_out, ECB, RC2);
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
	}
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
		
	bzero(enc_out, enc_out_size);
	bzero(dec_out, dec_out_size);
	
	printf("	+++++++++++++++++++++ Operative Mode: OFB\n");
	printf("	ENCRYPTING");
	for(i = 0, enc_result = 0; i < 5; i++){
		memcpy(aux_iv_64, iv_64, sizeof(iv_64));
		start = clock();
		encrypt(in, in_size, key_128, aux_iv_64, enc_out, OFB, RC2);
		end = clock();
		enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		enc_result += enc_time;
	}
	printf("  Average Time ===> %lf\n", enc_result/5);
    
	printf("	DECRYPTING");
	for(i = 0, dec_result = 0; i < 5; i++){
		memcpy(aux_iv_64, iv_64, sizeof(iv_64));
		start = clock();
		decrypt(enc_out, enc_out_size, key_128, aux_iv_64, dec_out, OFB, RC2);
		end = clock();
		dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
		dec_result += dec_time;
	}
	printf("  Average Time ===> %lf\n", dec_result/5);
	printf("	SPEED RATIO for 5 times ==========> %lf\n\n", (enc_result/5)/(dec_result/5));
	
	free(enc_out);
	free(dec_out);
	
	//printf("%s\n%s\n", enc_out, dec_out);
		
    return 0;
}
