//Sha256 Algorithm

//explain stdio

//@Author Kevin Gleeson

//@Date 1/03/2019

#include<stdio.h>
#include<stdint>

void sha256();

//Sections 4.1.2 and 4.2.2 for definitions
uint32_t sig0(uint32_t x);
int32_t sig1(uint32_t x);


int main(int argc, char *argv[]){

  sha256();
  return 0;
  }

void sha256(){
  //Message Shedule (Section 6.2)
  uint32_t W[64];
  //Working Variables (Section 6.2)
  uint32_t a, b, c, d, e, f, g, h;

  //Two temporary variables (Section 6.2)
  uint32_t T1,T2; 

  //HAsh Value
  //Hex Values from (Section 5.3.3)
   uint32_t H[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
  };
  
  //Current Message Block array
  uint32_t M[16];
  
  // Loop variable
  int t;
  // Wt = mt (Page 22)
  for(t = 0; t < 16; t++){
    
    W[t] = M[t];
    
  {


  // (page 22)
  for(t = 16; t < 64; t++){
    sig_1 = (W[t-2)] + W[t-7} + sig_0(W[t-15]) + W[t-16];
    

  }
  
 }

uint32_t sig0(uint32_t x){


}
int32_t sig1(uint32_t x){

}


