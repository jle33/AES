/*

 * AESMain.cpp

 *
 *  Created on: Oct 26, 2012
 *      Author:James B Le
 */
#include <stdio.h>
#include <iostream>
#include <ctime> //to use the time function
#include <stdlib.h>
#include <string>
#include <vector>
#include <fstream>
using namespace std;

enum{
	Rounds = 10,
	blockSize = 4, //Should stay the same for the 4 x 4 blocks of the input block
	KeySize = 16
};
vector<unsigned char> oneShift(vector<unsigned char> shiftme);
vector<unsigned char> keyScheduleSubBytes(vector< unsigned char > w_i, vector< vector<unsigned char> > sbox);

int PlainTextSize = 0; //Keeping track the Size of the plain text for use in a function
int LastByteTouched = 0; //Used to keep track of the last byte touched for the input bytes - used for combining multiple 16 by 16 blocks

//128-bit key, so a 16 byte key
/*Generates a 128bit key for use with AES*/
void genKey(unsigned char* skey, int size){
	static const unsigned char EnGen[] = "0123456789abcdefghiklmnopqrstuvyzABCDEFGHIJKLMNOPQRSTUVYZ";
	const unsigned char maxAlSize = (sizeof(EnGen)-1);
	srand(time(0));
	for(int i = 0; i < size; i++){
		skey[i] = EnGen[rand() % maxAlSize];
	}
}


/*The first step in AES is to add the roundkey to the initial input state.
  The function will take in two vectors, an inputState and the first keyBlock of the Key Schedule 
  it will than xor the inputState wit the first block of the Key Schedule which will give an output
  state based on those two.
*/
//Tested Working!!
vector< vector<unsigned char> > initialRound(vector< vector<unsigned char> > inputState, vector< vector<unsigned char> > keyBlock/*Round 0 Block*/){
	vector< vector<unsigned char> > outputState(4, vector<unsigned char>(4));
	for(int i =0; i < blockSize; i++){
		for(int j=0; j < blockSize; j++){
			outputState[j][i] = inputState[j][i] ^ keyBlock[j][i];
		}
	}

	return outputState;
}

/*The S-Box I decided to hardcode it instead of figuring out how to automate it each time AES is runned.
Will return a 16 by 16 vector*/
vector< vector<unsigned char> > getSBox(){
	vector< vector<unsigned char> > sBox(16, vector<unsigned char>(16));
	unsigned char S_Box[16][16] = {
			{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
			{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
			{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
			{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
			{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
			{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
			{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
			{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
			{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
			{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
			{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
			{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
			{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
			{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
			{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
			{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
	};
	for (int i = 0; i < 16; i++){
		for(int j = 0; j < 16; j++){
			sBox[i][j] = S_Box[i][j];
		}
	}

	return sBox;
}
/*The key Expansion function takes in the initial keyblock and the S-Box, which than will follow the AES standard for 
expanding the key schedule. The Rcon is created automatically which that is used in the creation of the extra
40 keys*/
vector< vector<unsigned char> > keyExpansion(vector<vector<unsigned char> > keyblock, vector< vector<unsigned char> > SBox){
	vector< vector<unsigned char> > keySchedule(4, vector<unsigned char>(44));
	vector< vector<unsigned char> > Rcon(Rounds, vector<unsigned char>(4, 0)); //Switch up Rows and Columns

	int RconSize = Rounds;
	int RconPosition = 0;
	//Producing the Rcon
	unsigned char c=0x01;
	Rcon[RconPosition][0] = c;
	RconPosition++;
	while(RconSize > 1){
		unsigned char b;
		b = c & 0x80;
		c = c << 1;
		if(b==0x80){
			c = c ^ 0x1b;
		}
		Rcon[RconPosition][0] = c;
		/*
		for(int i =1; i<4;i++){
			Rcon[RconPosition][i] = 0x00;
		}*/
		RconPosition++;
		RconSize--;
	}
	RconPosition = 0;

	//Store CipherKey
	for(int i = 0; i < blockSize; i++){
		for(int j =0; j < blockSize; j++){
			keySchedule[i][j] = keyblock[i][j];
		}
	}

	vector< vector<unsigned char> > tempBlock(4, vector<unsigned char>(4));
	//The previous 1st word of the last block
	vector<unsigned char> preWi(4);
	//Column to RotWord and subBytes
	vector<unsigned char> WiColumn(4);
	//To store final column at end of XORs
	vector<unsigned char> Wi(4);
	int currentRconPos = 0;
	//countdown timer to next 3 way XOR
	int timer = 0;
	/*Next is the algorithem for the creation of the keys, the code below follows the steps required in its creation*/
		for(int j = 3; j < 43; j++){ //The j+1 from the last store should finish it off. so everything is done.
			if(timer == 0){
				//Storing column into temp column
				for(int k =0; k < 4; k++){
					WiColumn[k] = keySchedule[k][j];
					preWi[k] = keySchedule[k][j-3];
				}
				//RotWord
				WiColumn = oneShift(WiColumn);
				WiColumn = keyScheduleSubBytes(WiColumn, SBox);
				//Start XOR with Wi-3 with WiColumn and RCon
				for(int x = 0; x < 4; x++){
					Wi[x] = preWi[x] ^ WiColumn[x] ^ Rcon[currentRconPos][x];
				}
				//Need to store onto keySchedule
				for(int y = 0; y < 4; y++){
					keySchedule[y][j+1] = Wi[y];
				}
				currentRconPos++;//Increment to next word in Rcon
				timer = 3; //Should be 3 to next 3 way XOR thingy
			}
			else{	 
				for(int k =0; k < 4; k++){
					WiColumn[k] = keySchedule[k][j];
					preWi[k] = keySchedule[k][j-3];
				}
				for(int x = 0; x < 4; x++){
					Wi[x] = preWi[x] ^ WiColumn[x];
				}
				for(int y = 0; y < 4; y++){
					keySchedule[y][j+1] = Wi[y];
				}
				timer--;//Start countdown
			}
		}
	

	return keySchedule;
}

//For the expanding key *subBytes* 1D
/*This function is for the key Expansion, it does Substitution Bytes required*/
vector<unsigned char> keyScheduleSubBytes(vector< unsigned char > w_i, vector< vector<unsigned char> > sbox){
	unsigned char byte;
	int row = 0;
	int column = 0;
	for(int i =0; i < 4; i++){
		byte = w_i[i];
		row = (byte >> 4 & 0xf);
		column = (byte & 0xf);
		w_i[i] = (sbox[row][column]);
	}
	return w_i;
}

/*SubBytes function, basically it will just map the hex values within the inputState to the S-Box
ex. Hex: 0x3e will be at (3,e) in the S-Box which is were you replace the values within the inputState
of that of the S-Box state*/
//Tested working!
vector< vector<unsigned char> > subBytes(vector< vector<unsigned char> > inputState, vector< vector<unsigned char> > SBox){
	vector< vector<unsigned char> > state(blockSize, vector<unsigned char>(blockSize));
	unsigned char byte;
	int row = 0;
	int column = 0;

	for(int i = 0; i < 4; i++){
		for(int j = 0; j < 4; j++){
			byte = inputState[j][i]; //going each row, for the current column
			row = (byte >> 4 & 0xf);
			column = (byte & 0xf);
			state[j][i] = (SBox[row][column]);
		}
	}
	return state;
}

/*ShiftRows -oneShift- this just shifts the rows once. Will be called based on how many times you want to shift*/
//used in shiftRows and key Schedule, reason why this is not in shiftRows.
vector<unsigned char> oneShift(vector<unsigned char> shiftme){
	unsigned char temp = 0;
	int i = 0;
	temp = shiftme[0];
	while((i+1) != blockSize){
		shiftme[i] = shiftme[i+1];
		i++;
	}
	shiftme[3] = temp;

	return shiftme;
}
/*shiftRows this will just take in the inputstate and shift the rows based on the rows
calls oneShift() to shift the rows*/
//Tested working!
vector< vector<unsigned char> > shiftRows(vector< vector<unsigned char> > inputState){
	vector<vector<unsigned char> > state(blockSize, vector<unsigned char>(blockSize));
	//1st shift
	state[0] = inputState[0];
	//2nd shift
	state[1] = oneShift(inputState[1]);
	//3rd shift
	state[2] = oneShift(inputState[2]);
	state[2] = oneShift(state[2]);
	//4th shift
	state[3] = oneShift(inputState[3]);
	state[3] = oneShift(state[3]);
	state[3] = oneShift(state[3]);
	return state;
}

/*getr - Part of mix columns
does the multiplication part of mix columns part
*/
unsigned char getr(unsigned char a_k, unsigned char hex){
	if(hex == 0x01){
		return a_k;
	}
	else if(hex == 0x02){
		//if leftmost bit is 1, anything times 2 is greater than 255
		if(((a_k & 0xff) >> 7) == 1){
			a_k = (a_k << 1);
			a_k = (a_k ^ 0x1b);
		}
		else{
			a_k = (a_k << 1);
		}
		return a_k;
	}
	else{//hex == 0x03
		unsigned char temp = 0x0;
		//split 0x03 into 0x02 XOR 0x01...look at mix_columns.pdf
		if(((a_k & 0xff) >> 7) == 1){
			temp = (a_k << 1);
			temp = (temp ^ 0x1b);
		}
		else{
			temp = (a_k << 1);
		}
		a_k = (temp ^ a_k);
	}
	return a_k;
}

/*mixColumns - the inner most loop gets the value between two values specified by the mix columns
it than saves the value within an array that will keep track of whats in the new row. Basically this 
whole function does matrix muliplication but in a bitwise manner.*/
vector<vector<unsigned char> > mixColumns(vector< vector<unsigned char> > inputState){
	vector<vector<unsigned char> > state(blockSize, vector<unsigned char>(blockSize)); //make sure to declare sizes first
	unsigned char rValues[4];
	//unsigned char r[4];
	unsigned char mixColumn[4][4] = {
			{0x02, 0x03, 0x01, 0x01},
			{0x01, 0x02, 0x03, 0x01},
			{0x01, 0x01, 0x02, 0x03},
			{0x03, 0x01, 0x01, 0x02}
	};
	//rule: multiplication of a value by x(i.e 02) is a 1-bit left shift followed by XOR with 1B(00011011)
	//Only used when leftmost bit is a 1 so >> 7 times;
	for(int k = 0; k < blockSize; k++){
		for(int i =0; i<blockSize; i++){
			for(int j=0; j < blockSize; j++){
				rValues[j] = getr(inputState[j][k], mixColumn[i][j]);
			}
			state[i][k] = rValues[0] ^ rValues[1] ^ rValues[2] ^ rValues[3];
		}
	}
	return state;
}

/*addRoundKey - This function does what it does, just adds the next round key to the inputState passed*/
//Tested Working!
vector<vector<unsigned char> > addRoundKey(vector< vector<unsigned char> > inputState, vector< vector<unsigned char> > roundKey){
	vector<vector<unsigned char> > state(blockSize, vector<unsigned char> (blockSize)); //make sure to declare sizes first
	for(int i = 0; i < blockSize; i++){
		for(int j = 0; j < blockSize; j++){
			state[j][i] = inputState[j][i] ^ roundKey[j][i];
		}
	}
	return state;
}

/*This function will convert the array mainly the key and plaintext specified into a 4 by 4 matrix for
the AES algorithem to work*/
vector< vector<unsigned char> > convertToByteArray(const unsigned char array[], bool lastByte, int type){
	vector< vector<unsigned char> > Block(blockSize, vector<unsigned char>(blockSize));
	int increment = 0;
	if(lastByte != 0)
		increment = LastByteTouched;
	for(int i = 0; i < blockSize; i++){
		for (int j = 0; j < blockSize; j++){
			if((increment >= (PlainTextSize)) && (type == 1)){
				Block[j][i] = 0x00;
			}
			else{
				Block[j][i] = array[increment++];
			}
		}
	}
	if(lastByte != 0)
		LastByteTouched = increment;
	return Block;
}

//Prints whats in matrix in char format
void printMatrixDebug(vector< vector<unsigned char> > TheBlock){
	printf("\n");
	printf("%c %c %c %c\n", TheBlock[0][0], TheBlock[0][1], TheBlock[0][2], TheBlock[0][3]);
	printf("%c %c %c %c\n", TheBlock[1][0], TheBlock[1][1], TheBlock[1][2], TheBlock[1][3]);
	printf("%c %c %c %c\n", TheBlock[2][0], TheBlock[2][1], TheBlock[2][2], TheBlock[2][3]);
	printf("%c %c %c %c\n", TheBlock[3][0], TheBlock[3][1], TheBlock[3][2], TheBlock[3][3]);
	printf("\n");
}
//Prints whats in matrix in hex format
void printHexDebug(vector< vector<unsigned char> > TheBlock){
	printf("\n");
	printf("%x %x %x %x\n", (TheBlock[0][0] & 0xff), (TheBlock[0][1] & 0xff), (TheBlock[0][2] & 0xff), (TheBlock[0][3] & 0xff));
	printf("%x %x %x %x\n", (TheBlock[1][0]& 0xff), (TheBlock[1][1]& 0xff), (TheBlock[1][2]& 0xff), (TheBlock[1][3]& 0xff));
	printf("%x %x %x %x\n", (TheBlock[2][0]& 0xff), (TheBlock[2][1]& 0xff), (TheBlock[2][2]& 0xff), (TheBlock[2][3]& 0xff)); ;
	printf("%x %x %x %x\n", (TheBlock[3][0]& 0xff), (TheBlock[3][1]& 0xff), (TheBlock[3][2]& 0xff), (TheBlock[3][3]& 0xff));
	printf("\n");
}

/*This will get the next keyblock within the key schedule. The round key is based on the current round of the AES algorithem*/
//Guess this works, don't need initialRound anymore
//Getting Roundkey, ie round 0 is 0*4 = 0, round 1 is 1*4 = 4, round 2 is 2*4 = 8...etc for the starting position of each round
vector< vector<unsigned char> > getRoundKey(vector< vector<unsigned char> > keySche, int curRound){
	curRound = curRound * 4;
	vector< vector<unsigned char> > RoundBlock(4, vector<unsigned char>(4));
	int x = 0;
	int y = 0;
	for(int i = 0; i < 4; i++){
		y=0;
		for(int j = curRound; j < (curRound+4); j++){
			RoundBlock[x][y] = keySche[i][j];
			y++;
		}
		x++;
	}


	return RoundBlock;
}

/*This function just converts the block array into a 1D array*/
vector<unsigned char> convertBack(vector< vector<unsigned char> > output){
	vector<unsigned char> arr(16);
	int x = 0;
	for(int i = 0; i < 4; i++){
		for(int j =0; j < 4; j++){
			arr[x] = output[j][i];
			x++;
		}
	}

	return arr;
}

int main(){
	unsigned char key[KeySize];
	char UserChoice[2];
	char stringr [16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	int choice = 0;
	bool runit = true;
	/*USER INTERFACE TEXT*/
	/*
	while(runit){
	printf( "Please input either 1 for a 16 byte generated key or 2 for user specified key.  0 is to exit\n");
	printf("UserChoice: ");
	fgets(UserChoice, 3,stdin);
	choice = atoi(UserChoice);
		if(choice == 1){
			genKey(key, KeySize);
			printf("Key: ");
			for(int i = 0; i < KeySize; i++){
				printf("%c",key[i]);
			}
			printf("\n");
			printf("Hex Version: ");
			for(int i = 0; i < KeySize; i++){
				printf("%x", key[i]);
			}
			printf("\n");
			runit = false;
		}else if(choice == 2){
				printf("Please enter a 16 byte string\n");
				printf("Your Key: " );
				fgets(stringr, 17, stdin);
				for(int i = 0; i < KeySize; i++){
					key[i] = stringr[i];
				}
				printf("Key: ");
				for(int i = 0; i < KeySize; i++){
					printf("%c",key[i]);
				}
				printf("\n");
				printf("Hex Version: ");
				for(int i = 0; i < KeySize; i++){
					printf("%x", key[i]);
				}
				printf("\n");
				printf("Is this correct? Enter 1 to continue or 0 to try again\n");
				printf("UserChoice: ");
				fgets(UserChoice, 3, stdin);
				choice = atoi(UserChoice);
				if(choice == 1){
					runit = false;
				}else{
					runit = true;
				}
				
		}else if(choice == 0){
			runit = false;
			return 0;
		}
		else{
			printf("Invalid input %d\n", choice);
			printf("Please try again \n");
		}
	}
	
	*/
	




	/*###############################TEST CASE 1 Start#####################################*/
	/*fips-197.pdf (http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
	Appendix B – Cipher Example
	PlainText: 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34 
	Cipher Key: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
	*/
	/*Used the website http://testprotect.com/appendix/AEScalc to test if it works
	copy and paste the above PlainText and Cipher key into the two associated boxes.
	*/
	/*
	printf("Plain Text\n");
	const unsigned char Plaintext[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	printf("%s\n", Plaintext);
	PlainTextSize = sizeof(Plaintext);
	const unsigned char EnterKey[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	for(int i = 0; i < KeySize; i++){
		key[i] = EnterKey[i];
	}
	*/
	/*###############################TEST CASE 1 End#####################################*/



	/*###############################TEST CASE 2 Start#####################################*/
	//Used the website http://people.eku.edu/styere/Encrypt/JS-AES.html to see whats happening.
	
	printf("Plain Text\n");
	const unsigned char Plaintext[] = "THIS IS A TEST";
	printf("%s\n", Plaintext);
	PlainTextSize = sizeof(Plaintext);
	const unsigned char EnterKey[] = {0xf6, 0xcc, 0x34, 0xcd, 0xc5, 0x55, 0xc5, 0x41, 0x82, 0x54, 0x26, 0x02, 0x03, 0xad, 0x3e, 0xcd };
	for(int i = 0; i < KeySize; i++){
		key[i] = EnterKey[i];
	}
	
	/*###############################TEST CASE 2 End#####################################*/

	//Initilize S Box
	vector< vector<unsigned char> > s_box = getSBox();
	//conver Key to block Byte, than expand that key to 44 round keys
	vector< vector<unsigned char> > keyBlock = convertToByteArray(key, false, 0);
	//Expand the key
	vector< vector<unsigned char> > keySchedule = keyExpansion(keyBlock, s_box);
	//Get roundkey
	vector< vector<unsigned char> > RoundKeyBlock = getRoundKey(keySchedule, 0);
	//Convert to 2D Block
	vector< vector<unsigned char> > inputState = convertToByteArray(Plaintext, false, 1);
	
	printf("\nINITIAL KEY");
	printHexDebug(RoundKeyBlock);

	printf("HEX VERSION OF PLAINTEXT");
	printHexDebug(inputState);

	/*
	printf("Round Key\n");
	for(int i = 0; i <4; i++){
		for(int j = 0; j < 44; j++){
			if(j%4 == 0){
				printf("\t");
			}
			printf("%x", keySchedule[i][j]);
		}
		printf("\n");
	}*/


	vector< vector<unsigned char> > outputState(4, vector<unsigned char>(4));
	/*The algorithem for AES, this for loop just follows the steps for he AES algorithem*/
	for(int i = 0; i < Rounds+1; i++){
		printf("Round %d\n", i);
		if(i == 0){
			outputState = addRoundKey(inputState, RoundKeyBlock);
			inputState = outputState;
			printHexDebug(inputState);
		}
		else if(i == (Rounds)){//last round
			//do not do mix columns
			outputState = subBytes(outputState, s_box);
			outputState = shiftRows(outputState);
			RoundKeyBlock = getRoundKey(keySchedule, i);
			outputState = addRoundKey(outputState, RoundKeyBlock);
			printHexDebug(outputState);
		}
		else{
			outputState = subBytes(outputState, s_box);
			outputState = shiftRows(outputState);
			outputState = mixColumns(outputState);
			RoundKeyBlock = getRoundKey(keySchedule, i);
			outputState = addRoundKey(outputState, RoundKeyBlock);
			printHexDebug(outputState);
		}

	}

	printf("Block Output: ");
	printHexDebug(outputState);

	printf("Output: ");
	vector<unsigned char> cipher = convertBack(outputState);
	int i = 0;
	while(i != cipher.size()){
		printf("%x",cipher[i]);
		i++;
	}
	printf("\n");

	return 0;
}



