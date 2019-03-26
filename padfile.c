//Padding file for the sha256 algorithm

//@ Author Kevin Gleeson

// Date: 25/03/2019

//Include stdio and stdint.
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
// unoins are used to store each member variable in the same memory location.
// This allows for assigning  different variable types dynamically from the same memory block.
// The Unoin below can access the msgblock and we can call the different unsigend intergers at any time from the same memory location. 
union msgblock{
  // To acces the message block as bytes
  uint8_t e[64];
  // To acces the message block as 32-bit integer 
  uint32_t t[16];
  // To access the message block as eight 64-bit intergers
  uint64_t s[8];
};

// enum used for flags for reading a file, finished reading a file,
// PAD1 for padding the message, PAD0 for no padding needed.
// represented as 0, 1, 2, 3.  
enum status {READ, PAD0, PAD1, FINISH};

// Adapted from https://stackoverflow.com/questions/45307516/c-c-code-to-convert-big-endian-to-little-endian
// Function to convert little endian bit ordering to big endian. 
uint64_t swap(uint64_t k){

  return ((k << 56) |
          ((k & 0x000000000000FF00) << 40) |
          ((k & 0x0000000000FF0000) << 24) |
          ((k & 0x00000000FF000000) << 8) |
          ((k & 0x000000FF00000000) >> 8) |
          ((k & 0x0000FF0000000000) >> 24) |
          ((k & 0x00FF000000000000) >> 40) |
          (k >> 56)
          );
}
 /* Condidition for endian check
  * Adapted from: https://stackoverflow.com/questions/8571089/how-can-i-find-endian-ness-of-my-pc-programmatically-using-c 
  * The above num varaible is 01 in binary
  * If little endian it will be 10.
  * The below statment caeck the leftmost char in the binary string.
  * if the first char is 1 it means the system is little endian.
  * We then need to reverse the order of the bits to convert the ordering to big endian as per the instruction within 
  * the sha256 specifctaion document.
  */
int checkEndian(){
	// Variable to be used check for endian system type.
	int num = 0x01;
	// If the first char is 1 it's littel endian
	if (*(char *)&num == 1)
  {
     printf("The system is Little-Endian message block converted to big endian\n");
	 return 1;
  }
  // It's Big endian
  else
  {
	printf("The system is Big-Endian no need to convert\n");
	return 0;
  }
	
}
int main(int argc, char *argv[]) {
 
  // Access the messageblock
  union msgblock M;
  // value for appending to end of last message block
  uint64_t nobits = 0; 
  // store the number of bytes read from the file.
  uint64_t nobytes; 
  // set enum status to read.
  enum status S = READ;
  // declare A file pointer from cmd input
  FILE* f;
   // open the file from the first  argument in the command line
  f = fopen(argv[1], "r");
  //Error check for file input.
  // Adapted from: https://stackoverflow.com/questions/48634880/c-reading-files-passed-as-command-line-argument
  if(f == NULL){
	//Print the error to the user.
    perror("fopen");
    exit(EXIT_FAILURE);
  }
  // Loop control variable.
  int i;
  //Keep looping while enum set to read.
  while(S == READ) {
    nobytes =  fread(M.e, 1, 64, f);
	//print out number of bytes read
    printf("Read %211u bytes\n", nobytes);
	//get the size of the file as bits
    nobits = nobits + (nobytes * 8);
	//get to last eight bytes of the file
    if(nobytes < 56) {
	  //print message to user
      printf("I've found a block with less than 55 bytes!\n");
	  //set to 1 followed by 7 zeros
      M.e[nobytes] = 0x80;
	  //loop unitl the end of the last block
      while (nobytes < 56) {
		//add 1 to nobytes to acces next index
        nobytes = nobytes + 1;
		//Set all bytes to zero up to the last eight bytes
		// The size of the file will be the last part of the block
        M.e[nobytes] = 0x00;
      }
	//Truth vaule for endian
	if(checkEndian() == 1){
		//@todo ensure message is big endian
		//set the last element of M to the size of the file in bits
		//Swap the ordering to big endian
		M.s[7] = swap(nobits);
	}
	else
	{
		//@todo ensure message block is in big endian
		//Set the last element o M to the size of the file in bits
		M.s[7] = nobits;
	}
      //Set enum to finish to exit loop.
      S = FINISH;
	  // Condition to check if there isn't enouhg room to add padding to the end of the file.
    } else if (nobytes < 64) {
		// States that we need another message block of all zeros
        S = PAD0;
		// Set the message block e to 1 followed by 7 zero's
        M.e[nobytes] = 0x80;
		// Loop to end of message block to add all zeros
        while(nobytes < 64) {
		  //Access the next index in array.
          nobytes = nobytes + 1;
		  // Set to zero
          M.e[nobytes] = 0x00;
        }
	  // check if end of file reached and the file size is exactly 
	  // a multiple of 64 bytes
      }else if(feof(f)){
		// set enum to PAD1.
        S = PAD1;    
      }
  }
  //Condition to check for PAD0 or PAD1 flags.
  //If eaither are true there still needs to be additional padding added to the file.  
  if (S == PAD0 || S == PAD1) {
	// loop up the the last 8 bytes of the block
    for (i = 0; i < 56; i++){
	  //add zeros
      M.e[i] = 0x00;
    }
	// Add the hex value of the file size to end of the message block. 
    M.s[7] = nobits;
  }
  if (S == PAD1){
	// Add 1 followed by 7 zeros
    M.e[0] = 0x80;
  }
  //Close the file beling read
  fclose(f);
  // Print out the last message block.
  for (int i = 0;i < 64; i++)
    printf("%x ", M.e[i]);
  printf("\n");


  return 0;
}    
