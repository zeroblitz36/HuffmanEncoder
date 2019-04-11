#pragma once
#include <inttypes.h>
#include <stdlib.h>
#include <stddef.h>

#define MAX_NODE_COUNT 512
struct HuffmanTree{
	uint64_t code[MAX_NODE_COUNT];
	uint64_t count[MAX_NODE_COUNT];
	uint16_t left[MAX_NODE_COUNT];
	uint16_t right[MAX_NODE_COUNT];
	uint8_t codeLength[MAX_NODE_COUNT];
	uint16_t nodeCount;
	uint16_t rootNode;
};

uint16_t createHuffmanTreeStructure(struct HuffmanTree *h){
	uint8_t viz[MAX_NODE_COUNT] = {0};
	int unvisitted = 256;

	int i,min1,min2,man;

	for(i=0;i<256;++i){
		if(!h->count[i]){
			viz[i] = 1;
			--unvisitted;
		}
	}

	while(unvisitted > 1){
		for(i=0;i<h->nodeCount;++i){
			if(!viz[i]){
				min1 = i;
				break;
			}
		}
		for(i=i+1;i<h->nodeCount;++i){
			if(!viz[i]){
				min2 = i;
				break;
			}
		}
		if(h->count[min2] < h->count[min1]){
			man = min1;
			min1 = min2;
			min2 = man;
		}
		for(i=i+1;i<h->nodeCount;++i){
			if(viz[i])continue;
			if(h->count[i] <= h->count[min1]){
				min2 = min1;
				min1 = i;
			}else if(h->count[i] < h->count[min2]){
				min2 = i;
			}
		}
		viz[min1] = 1;
		viz[min2] = 1;

		h->code[h->nodeCount] = 0;
		h->codeLength[h->nodeCount] = 0;
		h->left[h->nodeCount] = min2;
		h->right[h->nodeCount] = min1;
		h->count[h->nodeCount] = h->count[min2] + h->count[min1];
		h->nodeCount++;
		--unvisitted;
	}
	return h->nodeCount-1;
}

void recursiveHuffmanCodeCreation(struct HuffmanTree *h, uint16_t nodeId, uint64_t code, uint8_t codeLength){
	//printf("Found code for 0x%03hhx with length = %d code = 0x%" PRIx64 "\n", nodeId, codeLength, code);
	if(nodeId > 255){
		++codeLength;
		recursiveHuffmanCodeCreation(h,h->left[nodeId],code,codeLength);
		code |= ((uint64_t)1 << (codeLength - 1)); 
		recursiveHuffmanCodeCreation(h,h->right[nodeId],code,codeLength);
		return;
	}
	h->code[nodeId] = code;
	h->codeLength[nodeId] = codeLength;
}

void initializeHuffmanTree(struct HuffmanTree *h, uint64_t *v){
	h->nodeCount = 256;
	for(int i=0;i<256;++i){
		h->code[i] = 0;
		h->codeLength[i] = 0;
		h->left[i] = MAX_NODE_COUNT;
		h->right[i] = MAX_NODE_COUNT;
		h->count[i] = v[i];
	}
	h->rootNode = createHuffmanTreeStructure(h);
	recursiveHuffmanCodeCreation(h,h->rootNode,0,0);
}

uint8_t* encryptData(struct HuffmanTree *h, const uint8_t *data, size_t dataLength, size_t *outEncryptedDataLength){
	size_t cap = dataLength;
	if(cap < 10000){
		cap = 10000;
	}
	uint8_t *buffer = malloc(cap);
	if(!buffer){
		printf("Could not allocate buffer of length %zu for encryption\n", cap);
		exit(1);
	}
	size_t s = 0;
	uint8_t workCharacter = 0;
	int workCharacterIndex = 7;

   //encode the dataLength
   for(int8_t i=7*8;i>=0;i-=8){
      buffer[s] = (uint8_t)(dataLength>>i);
      //printf("buffer[%" PRIu64 "] = 0x%02hhx\n", s, buffer[s]);
      ++s;
   }

	//encode the tree in the file
	int n = h->rootNode - 255;
	//printf("encryptData: internal node count %d\n",n);
	buffer[s] = (uint8_t) n;
	++s;
	for(int j=h->rootNode;j>255;--j){
		for(int i=8;i>=0;--i){
			workCharacter |= ((h->left[j]>>i)&1) << workCharacterIndex;
			--workCharacterIndex;
			if(workCharacterIndex < 0){
				++s;
				buffer[s-1] = workCharacter;
				workCharacterIndex = 7;
				workCharacter = 0;
			}
		}
		for(int i=8;i>=0;--i){
			workCharacter |= ((h->right[j]>>i)&1) << workCharacterIndex;
			--workCharacterIndex;
			if(workCharacterIndex < 0){
					++s;
					buffer[s-1] = workCharacter;
					workCharacterIndex = 7;
					workCharacter = 0;
			}
		}
		//printf("encryptData: internal node %d left node %d right node %d\n", j, h->left[j], h->right[j]);
	}

	//write the encrypted data
	for(size_t j=0;j<dataLength;++j){
		const uint64_t code = h->code[data[j]];
		const uint8_t codeLength = h->codeLength[data[j]];
		for(int i=0;i<codeLength;++i){
			workCharacter |= ((code>>i)&1) << workCharacterIndex;
			--workCharacterIndex;
			if(workCharacterIndex < 0){
				++s;
				if(s > cap){
					cap*=2;
					uint8_t *tempBuffer = realloc(buffer, cap);
					if(!tempBuffer){
						printf("Could not reallocate buffer of length %zu for encryption\n", cap);
						exit(1);
					}
					buffer = tempBuffer;
				}
				buffer[s-1] = workCharacter;
				workCharacterIndex = 7;
				workCharacter = 0;
			}
		}
	}
	if(workCharacterIndex < 7){
		++s;
		if(s > cap){
			++cap;
			uint8_t *tempBuffer = realloc(buffer, cap);
			if(!tempBuffer){
				printf("Could not reallocate buffer of length %zu for encryption\n", cap);
				exit(1);
			}
			buffer = tempBuffer;
		}
		buffer[s-1] = workCharacter;
	}   
	//be nice and resize the buffer back down
	buffer = realloc(buffer, s);
	*outEncryptedDataLength = s;
	return buffer;
}

uint8_t getBit(const uint8_t *data, uint64_t index){
	const uint64_t i = index>>3;
	const uint8_t j = 7 - (uint8_t)(index&7);
	return (data[i]>>j) & 1;
}

uint8_t* decryptData(const uint8_t *data, size_t dataSize, size_t *outDecryptedDataSize){
   //decode the dataLength
	size_t sz = 0;
   for(uint8_t i=0;i<8;++i){
      sz |= (uint64_t)data[i] << ((7-i)*8);
   }
   *outDecryptedDataSize = sz;

	const int n = data[8];
	//printf("decryptData: internal node count %d\n",n);
	struct HuffmanTree h;
	h.nodeCount = n + 255 + 1;
	h.rootNode = h.nodeCount - 1;
	int currentNode;
	//decode the tree structure
	uint64_t s = 8*9;
	for(int j=n;j>0;--j){
		currentNode = j + 255;
		int left = 0;
		for(int i=8;i>=0;--i){
			left |= (getBit(data,s) << i);
			++s;
		}
		int right = 0;
		for(int i=8;i>=0;--i){
			right |= (getBit(data,s) << i);
			++s;
		}
		h.left[currentNode] = left;
		h.right[currentNode] = right;
		//printf("decryptData: internal node %d left node %d right node %d\n", currentNode, h.left[currentNode], h.right[currentNode]);
	}
	recursiveHuffmanCodeCreation(&h,h.rootNode,0,0);

	uint8_t *buffer = malloc(sz);

	currentNode = h.rootNode;
	const uint64_t numberOfBitsInData = dataSize * 8;
	const ptrdiff_t deltaLeftToRight = h.right-h.left;

	int j = s/8;
	int i = 7-s%8;
   int k = 0;
	for(;j<dataSize;++j){
		const uint8_t a = data[j];
		for(;i>=0;--i){
			currentNode = (h.left + ((a>>i)&1) * deltaLeftToRight)[currentNode];
			if(currentNode < 256){
				buffer[k] = (uint8_t)currentNode;
            ++k;
            if(k >= sz){
               return buffer;
            }
				currentNode = h.rootNode;
			}
		}
		i = 7;
	}
	return buffer;
}