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
	if (*(char *)&num == 1)
  {
     printf("The system is Little-Endian message block converted to big endian\n");
	 return 1;
  }
  else
  {
	printf("The system is Big-Endian no need to convert\n");
	return 0;
  }
	
}
int main(int argc, char *argv[]) {
 

  // Access the messageblock
  union msgblock M;
  // 
  uint64_t nobits = 0; 
  // store the number of bytes read from the file.
  uint64_t nobytes; 

  enum status S = READ;
  // declare A file pointer from cmd input
  FILE* f;
   // open the file from the first  argument in the command line
  f = fopen(argv[1], "r");
  //Error check for file input.
  // Adapted from: https://stackoverflow.com/questions/48634880/c-reading-files-passed-as-command-line-argument
  if(f == NULL){
    perror("fopen");
    exit(EXIT_FAILURE);
  }
  
  int i;  
  while(S == READ) {
    nobytes =  fread(M.e, 1, 64, f);
    printf("Read %211u bytes\n", nobytes);
    nobits = nobits + (nobytes * 8);
    if(nobytes < 56) {
      printf("I've found a block with less than 55 bytes!\n");
      M.e[nobytes] = 0x80;
      while (nobytes < 56) {
        nobytes = nobytes + 1;
        M.e[nobytes] = 0x00;
      }
 
	if(checkEndian() == 1){
     //@todo ensure message is big endian
     M.s[7] = swap(nobits);
  }
  else
  {
    //@todo ensure message block is in big endian 
    M.s[7] = nobits;
  }
      
      S = FINISH;      
    } else if (nobytes < 64) {
        S = PAD0;
        M.e[nobytes] = 0x80;
        while(nobytes < 64) {
          nobytes = nobytes + 1;
          M.e[nobytes] = 0x00;
        }          
      }else if(feof(f)){
        S = PAD1;    
      }
  }

  if (S == PAD0 || S == PAD1) {
    for (i = 0; i < 56; i++){
      M.e[i] = 0x00;
    }
    M.s[7] = nobits;
  }
  if (S == PAD1){
    M.e[0] = 0x80;
  }
  
  fclose(f);
  
  for (int i = 0;i < 64; i++)
    printf("%x ", M.e[i]);
  printf("\n");


  return 0;
}    
