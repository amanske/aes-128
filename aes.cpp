/*

Brief description of AES. Source: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

1. KeyExpansions—round keys are derived from the cipher key using Rijndael's key schedule. AES requires a separate 128-bit round key block for each round plus one more.
2. InitialRound
	1. AddRoundKey—each byte of the state is combined with a block of the round key using bitwise xor.
3. Rounds
	1. SubBytes—a non-linear substitution step where each byte is replaced with another according to a lookup table (s-box).
	2. ShiftRows—a transposition step where the last three rows of the state are shifted cyclically a certain number of steps.
	3. MixColumns—a mixing operation which operates on the columns of the state, combining the four bytes in each column.
	4. AddRoundKey
4. Final Round (no MixColumns)
	1. SubBytes
	2. ShiftRows
	3. AddRoundKey.

Encrypt with a total of 10 rounds for 128-bit AES

*/

#include <stdio.h>
#include <iostream>
#include <string>
#include <fstream>

using namespace std;

/* 16x16 S-box, fetched from https://en.wikipedia.org/wiki/Rijndael_S-box, used for the SubBytes step */
unsigned char sBox[256] =   {

0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
}; 

/* 16x16 rcon, fetched from https://en.wikipedia.org/wiki/Rijndael_key_schedule, used for deriving a subkey in the 
	AddRoundKey step and when expanding keys*/
unsigned char rcon[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};


/* Core function, applying sBox to the given word and XOR the left-most byte with the rcon map */
void key_schedule_core(unsigned char *t, int rcon_i){
	/* Rotate the word, to the left, meaning t[0] = t[1], t[1] = t[2], t[2] = t[3], t[3] = t[0] */ 
    unsigned char temp;
    temp = t[0];
    for (int i = 0; i < 3; ++i){
        t[i] = t[i+1];
    }
    t[3] = temp;
    /* ----------Rotation finished ---------*/
    for(int i = 0; i < 4; ++i){ //iterate over the word, apply sbox to each byte
    	t[i] = sBox[(t[i])];

    }
    t[0] = t[0] ^ rcon[rcon_i]; //for only the left-most byte, XOR with the rcon value based on the rcon index

}

/* 	Expands the key
	Theory implemented from https://en.wikipedia.org/wiki/Rijndael_key_schedule#The_key_schedule
*/
void expandKey(unsigned char *key, int key_size, unsigned char *expanded_key, int expanded_key_size){
	int rcon_i = 1; //rcon iteration value
	int current_size_of_key = 0; //stores the value of the current key size
	unsigned char t[4] = {0}; //temp variable of size 4 bytes


	for(int i = 0; i < key_size; ++i){ //copy the encryption key as the first 16 bytes in the extended key
		expanded_key[i] = key[i];
		current_size_of_key++;
	}
	while (current_size_of_key < expanded_key_size){ //loop until we meet the desired key size
		for(int i = 0; i < 4; ++i){
			t[i] = expanded_key[(current_size_of_key-4) + i]; //assign the value of the previous 4 bytes to t
		}
		if(current_size_of_key % key_size == 0){ //make sure that we only call core if we are in the intervals of a word
			key_schedule_core(t, rcon_i); //call the core function
			rcon_i++;
		}
		for(int i = 0; i < 4; ++i){
			//for each byte in the expanded key, store the value of the current expanded key byte - the size of the initial key
			// XOR'd with t
			expanded_key[current_size_of_key] = expanded_key[(current_size_of_key - key_size)] ^ t[i];
			current_size_of_key++;
		}
	}
}

/* Populate the state matrix with the current block of data to encrypt */
void populateState(unsigned char* to_encrypt, unsigned char** state){
	for(int i = 0; i < 4; ++i){
		for(int j = 0; j < 4; ++j){
			state[j][i] = to_encrypt[j + 4*i]; //fill each spot in the matrix with 1 of the 16 bytes of the data
		}
	}
}

/* Populate the round key matrix that will be used in the next AddRoundKey iteration. */
void populateRoundKey(unsigned char* expanded_key, unsigned char** round_key, int iter){
	for(int i = 0; i < 4; ++i){
		for(int j = 0; j < 4; ++j){
			round_key[j][i] = expanded_key[16*iter + j + 4*i];  //fill each spot with data from the expanded key,
																//moving up 16 bytes for each iteration
		}
	}	
}

/* Transfer the state to a (now encrypted) output byte array */
void populateOutput(unsigned char* cipher, unsigned char** state){
	for(int i = 0; i < 4; ++i){
		for(int j = 0; j < 4; ++j){
			cipher[j + 4*i] = state[j][i];  //fill each spot with data from the expanded key,
											//moving up 16 bytes for each iteration
		}
	}	
}

/* Perform the sub byte operation using the s-box */
void subBytes(unsigned char** state)
{
    for(int i=0; i<4; ++i)
    {
        for(int j=0 ;j<4 ;++j)
        {
            state[i][j] = sBox[(state[i][j])];
        }
    }
}

/* Perform the row shifting operation on the state matrix
   This picture is great for understading the shifts: 
   https://upload.wikimedia.org/wikipedia/commons/thumb/6/66/AES-ShiftRows.svg/810px-AES-ShiftRows.svg.png
*/
void shiftRows(unsigned char** state){
    unsigned char temp; //use temp variable to store rows during shifting

    //And just follow the illustration

    //Row 2
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    //Row 3
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    //Row 4
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

/* Perform the add round key operation, it combines the subkey with the state */
void addRoundKey(unsigned char** state, unsigned char** round_key){
	for(int i = 0; i < 4; ++i){
        for(int j = 0 ;j < 4; ++j)
        {
            state[i][j] = state[i][j] ^ round_key[i][j]; //Bitwise XOR on state and subkey
        }
	}
}

/* Helper function for the mix columns step 
   Implementation taken from https://en.wikipedia.org/wiki/Rijndael_mix_columns#Implementation_example */
void mixSingleColumn(unsigned char *r) {
        unsigned char a[4];
        unsigned char b[4];
        unsigned char c;
        unsigned char h;
        /* The array 'a' is simply a copy of the input array 'r'
         * The array 'b' is each element of the array 'a' multiplied by 2
         * in Rijndael's Galois field
         * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */ 
        for(c=0;c<4;c++) {
                a[c] = r[c];
                /* h is 0xff if the high bit of r[c] is set, 0 otherwise */
                h = (unsigned char)((signed char)r[c] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
                b[c] = r[c] << 1; /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
                b[c] ^= 0x1B & h; /* Rijndael's Galois field */
        }
        r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
        r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
        r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
        r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
}

/* Performs the mix columns step. Theory from: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_MixColumns_step */
void mixColumns(unsigned char** state){
    unsigned char *temp = new unsigned char[4];

    for(int i = 0; i < 4; ++i)
    {
        for(int j = 0; j < 4; ++j)
        {
            temp[j] = state[j][i]; //place the current state column in temp
        }
        mixSingleColumn(temp); //mix it using the wiki implementation
        for(int j = 0; j < 4; ++j)
        {
            state[j][i] = temp[j]; //when the column is mixed, place it back into the state
        }
    }
    delete temp;
}

int main(){
	unsigned char *key;
	unsigned char *input;
	//One block is 16 bytes (128 bits), initialize arrays:
	key = new unsigned char[16];
	input = new unsigned char[16];
	char block[16];
	cin.read(block,16); //Read a 16 bytes, store in block. This represents the key
	//now we need to store the key in the key array, but we need to cast each byte to an unsigned char
	for(int i = 0; i < 16; ++i){
		key[i] = (unsigned char) block[i];
	}
	//The key is now stored in the key array

	//Now, expand the key, theory implemented from https://en.wikipedia.org/wiki/Rijndael_key_schedule#The_key_schedule
    unsigned char expanded_key[176];

    //Call expandKey:
    //expandKey(unsigned char *key, int key_size, unsigned char *expanded_key, int expanded_key_size)
    expandKey(key, 16, expanded_key, 176);
  

    //Now, we create the state (the 4x4 matrix) and the round key (also 4x4) used in the addRoundKey step of the rounds
    unsigned char** state;
    //create the 4x4 state matrix
    state = new unsigned char*[4];
    for(int i = 0; i < 4; ++i){
    	state[i] = new unsigned char[4];
    }
    //each index in state now has 4 columns

    //create a round key using the same technique as above
    unsigned char** round_key;
    round_key = new unsigned char*[4];
    for(int i = 0; i < 4; ++i){
    	round_key[i] = new unsigned char[4];
    }

    //now we have finished the initial operations on the key, we will now read the data and implement the encryption
    unsigned char *to_encrypt;
    to_encrypt = new unsigned char[16]; //plaintext comes in blocks of 16 bytes
    while(cin.read(block,16)){
    	for(int i = 0; i < 16; ++i){
    		to_encrypt[i] = (unsigned char) block[i]; //cast data to byte size

    	}

    	//run initial round: AddRoundKey
    	
    	populateState(to_encrypt, state);
    	populateRoundKey(expanded_key, round_key, 0);
    	addRoundKey(state, round_key);


    	//first cycle done, do round 2-9:
    	for(int iter = 1; iter < 10; ++iter){
    		populateRoundKey(expanded_key, round_key, iter);
    		subBytes(state);
			shiftRows(state); 
			mixColumns(state); //TODO
			addRoundKey(state, round_key); 
    	}

    	//Last round
    	populateRoundKey(expanded_key, round_key, 10);
    	subBytes(state);
    	shiftRows(state);
    	addRoundKey(state, round_key);

    	//Done! Now transform the state to a byte array
    	
    	

    	populateOutput(to_encrypt, state);
    	//and print it to cout
    	for(int i = 0; i < 16; ++i){
    		cout << to_encrypt[i];
    	}
		
    }


}
