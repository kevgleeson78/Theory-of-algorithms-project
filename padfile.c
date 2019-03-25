//Padding file for the sha256 algorithm

//@ Author Kevin Gleeson

// Date: 25/03/2019

#include <stdio.h>
#include <stdint.h>
union msgblock{
  uint8_t e[64];
  uint32_t t[16];
  uint64_t s[8];
};

enum status {READ, PAD0, PAD1, FINISH};
// Adapted from https://stackoverflow.com/questions/45307516/c-c-code-to-convert-big-endian-to-little-endian
// Function to convert little endian to big endian. 
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

int main(int argc, char *argv[]) {
// Variable to be used check for endian
int num = 1;
  union msgblock M;
  
  uint64_t nobits = 0; 

  uint64_t nobytes; 

  enum status S = READ;
  
  FILE* f;
  f = fopen(argv[1], "r");
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
 //Condidition for endian check
  if (*(char *)&num == 1)
  {
     printf("The system is Little-Endian message block converted to big endian\n");
     //@todo ensure message is big endian
     M.s[7] = swap(nobits);
  }
  else
  {
    printf("The system is Big-Endian no need to convert\n");
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
