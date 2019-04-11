#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include "huffman_tree.h"
#include <string.h>

uint8_t* getEntireBinaryFile(const char* p, size_t *outBufferSize){
	FILE *f = fopen(p, "rb");
	if(!p){
		printf("Could not open the '%s' file for reading\n", p);
		exit(1);
	}
	fseek(f,0,SEEK_END);
	*outBufferSize = ftell(f);
	fseek(f,0,SEEK_SET);
	uint8_t *b = malloc(*outBufferSize);
	fread(b,1,*outBufferSize,f);
	return b;
}

void writeEntireBinaryFile(const char *p, const uint8_t *buffer, size_t s){
	FILE *f = fopen(p, "wb");
	if(!p){
		printf("Could not open the '%s' file for writing\n", p);
		exit(1);
	}
	fwrite(buffer,1,s,f);
	fclose(f);
}

int main(int argc, char **argv){
	if(argc != 2){
		printf("Usage : program filePath\n");
		exit(1);
	}
	size_t bufferSize = 0;
	printf("Reading file...\n");
	const uint8_t *buffer = getEntireBinaryFile(argv[1],&bufferSize);
	printf("Done!\n");
	uint64_t counts[256] = {0};
	for(size_t i=0;i<bufferSize;++i){
		++counts[buffer[i]];
	}

	printf("Creating huffman tree\n");
	struct HuffmanTree h;
	initializeHuffmanTree(&h, counts);

	printf("Encrypting data...\n");
	size_t encryptedDataLength = 0;
	const uint8_t *encryptedBuffer = encryptData(&h,buffer,bufferSize,&encryptedDataLength);
	printf("Writing to file...\n");
	char encryptedFileName[1024];
	strcpy(encryptedFileName, argv[1]);
	strcat(encryptedFileName, ".enc");
	writeEntireBinaryFile(encryptedFileName, encryptedBuffer, encryptedDataLength);
	printf("Encrypted data flushed to file\n");

	printf("Decrypting data...\n");
	size_t decryptedBufferLength = 0;
	const uint8_t *testDecryptBuffer = decryptData(encryptedBuffer, encryptedDataLength, &decryptedBufferLength);
	printf("Writing to file...\n");
	char testDecryptedFileName[1024];
	strcpy(testDecryptedFileName, argv[1]);
	strcat(testDecryptedFileName, ".dec");
	writeEntireBinaryFile(testDecryptedFileName,
		testDecryptBuffer,
	decryptedBufferLength);
	printf("Decrypted data flushed to file\n");

	return 0;
}