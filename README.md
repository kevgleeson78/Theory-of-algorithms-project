# SHA-256 in C

This application is an example of implementing the SHA-256 algorithm programmed in C.<br>
This repository holds a fourth year assignment for the module Theory of algorithms at [GMIT](http://gmit.ie) Galway.

Author: [Kevin Gleeson](https://github.com/kevgleeson78)

Fourth year student at: [GMIT](http://gmit.ie) Galway
## Cloning, compiling and running the application.

1: Download [git](https://git-scm.com/downloads) to your machine if not already installed.

1.1: For this project I have used an instance of a Debian system on the google cloud platform.<br>
This is used to compile and run the various files held within this repository. Please see below for further instruction on how to compile the files needed.

2: Open a command line and cd to the location you wish to clone the repository to.

 
 3: To clone the repository type the following command in the terminal.
```bash
>git clone https://github.com/kevgleeson78/Theory-of-algorithms-project
```
<br>
This will clone the repository to your machine

4: To compile the application cd to the Theory-of-algorithms folder and type the following command. 

```bash
> gcc -o sha256.c sha256
```
This will compile and create an executable file from the sha256.c file and name it sha256.

5: To run the application ensure you cd to folder the application is held.
Type the following commands: 
* The first argument is the executable.
* The second command is the file to be passed through the sha256 algorithm.
* You can choose any file you wish in the below example I have use a text file named test.txt with a paragraph of text.
```bash
> /sah256 test.txt
```
6: This will run the application and perform the sha-256 algorithm on test.txt.


# Background of project
The purpose of this project is to demonstrate in the C programming language an implementation of sha-256 encryption algorithm.<br/>
The development of the algorithm was aided by the use of the National Institute of Standards and Technology's [Secure Hash Standard (SHS)](https://www.nist.gov/publications/secure-hash-standard) describing how sha-256 should be implemented and structured.<br/> Below will explain how each phase of the development was completed and how each major function within the script relates to the SHS document's description of the algorithm. 


## The SHA-256 Algorithm
The sha-256 algorithm takes message of any length as input and splits the message into message blocks of 64 bytes. Padding is added to the last message block read to ensure uniqueness for the given input. Each of these message blocks have a hashing function performed on them to give an output that is always 256 bits in length and unique to the given input message. The secure hash algorithm sha-256 is a one way function where it is considered infeasible to obtain the input message from the 256 bit hashed output. The sections below will describe in more detail on how the algorithm works and how it was implemented in C.




## Implementing SHA-256
The below code snippets are from the sha256.c file held within this repository.
If you need a copy of National Institute of Standards and Technology's Secure Hash Standard (SHS) describing the below algorithm it can be found [here](https://www.nist.gov/publications/secure-hash-standard).
### Functions of Application:
This function will be used to hold the main body of the algorithm and will be called in the main function in sha256.c
```C
void sha256();
```
### Contents of sha356 function
#### K constants from section 4.2.2
The below array holds 64 fixed hex values.
Each Value in the array are the first thirty two bits of the cube roots of the first 64 prime numbers.
The values are used as a part of the formula to determine the value for the temporary variable T1 below.

```C
uint32_t K[] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2   
  };
  ```
  #### Message Shedule (Section 6.2)
This array expands the 512 bit message block into a 64 word array of each word being 32-bits in length, to be used in the below for loop.

```C
uint32_t W[64];
```
#### Working Variables (Section 6.2)
There are eight working variables needed to update the hash values with each iteration of the below loop.
```C
uint32_t a, b, c, d, e, f, g, h;
```
#### Temporary Variables (Section 6.2)
Two temporary variables are also used in the update of the has values within the below loop(Section 6.2)
```C
  uint32_t T1,T2; 
```
#### Hex Values from (Section 5.3.3)
The following 32-bit words are the initial hash values for the sha256 algorithm.
These values are the first 32-bits of the fractional parts of the square roots of
the first eight prime numbers.
Each value is assigned to the corresponding eight working variables a, b, c, ... , h as initial values in the first iteration of the algorithm.
```C
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
```

#### The array message block of 16 32-bit integers.
```C
uint32_t M[16] = {0, 0, 0, 0, 0, 0, 0 ,0};
```

```C
while (nextMessageBlock()){  
```
#### Wt = Mt (Page 22)
Assigns the first 16 32-bit integers to the message block to the word array W[].
Once this has been completed there are still 48 elements left to fill in the array.

```C
 for(t = 0; t < 16; t++){
      //Initialise the first 16 32-bit integers of M to W of the current message block.
      // There will be 48 elements left to fill in W. 
      W[t] = M[t];
    
    }
```

#### (page 22) filling the remaining elements from 16 - 64.
In the below loop the elements from 16 -64 in the W[] array are populated buy running the sig1 and sig0 functions on certain indices in the w W array (more details below...).

As discussed above the working variables a,b,c,...,h are initialised to each corresponding element of the h[] array.

```C
for(t = 16; t < 64; t++){
      // section 6.2.2
      // apply sig1 and sig0 to W - t(index in array W).
      W[t] =  sig1(W[t-2]) + W[t-7] + sig0(W[t-15]) + W[t-16];

      // Initialise working variables  a, b, c, d ,e ,f ,g ,h as per step 2, page 19.
      // each working variable gets assigned the hard coded values from the H array.
      a = H[0]; b = H[1]; c = H[2]; d = H[3];
      e = H[4]; f = H[5]; g = H[6]; h = H[7];   
    }
```
#### (section 6.6.2) assigning temporary variables T1 and T2 and updating working variables a,b,c...,h.
The below loop iterates through the 64 word message block and updates working variables a - h with each iteration. 
The temporary variable T1 is assigned the concatenation of the h working variable along with the tithe element of K[] and W[] and the output of the functions SIG1 and CH.
T2 is assigned the output of SIG0 and MAJ.
This continues until the loop has reached the end of the message block.
These functions will be explained further below.
```C
for( t = 0; t < 64; t++){
      T1 = h + SIG1(e) + Ch(e,f,g) + K[t] + W[t];
      T2 = SIG0(a) + Maj(a,b,c);
      // h =  old value of g.
      h = g;
      // g =  old value of f
      g = f;
      // f = old value of e
      f = e;
      // e = old value of d+T1
      e = d +T1;
      // d = old value of c
      d = c;
      // c = old value of b
      c = b;
      // b = old value of a
      b = a;
      // a = T1 + T2
      a = T1 + T2;        
    }
```
#### Updating the value of H[]
Finally the value for the H[] array is updated from the working variables.
This continues until the end of the input message has been reached (See padding section).
```C
    H[0] = a + H[0];
    H[1] = b + H[1];
    H[2] = c + H[2];
    H[3] = d + H[3];
    H[4] = e + H[4];
    H[5] = f + H[5];
    H[6] = g + H[6];
    H[7] = h + H[7];
```

### Bit shifting functions
#### rotr (rotate right)
The below function shifts the all bits down n bits with the bits at the end of the string comming back around to the start of the string.
```C
uint32_t rotr(uint32_t n, uint32_t x){
  
  return (x >> n) | (x << (32 - n));
  
}
```
#### shr (shift right)
The shr function shifts all bits down by n places with the bits falling off the end of the string are replaced by zeros at the start of the string. 
```C
uint32_t shr(uint32_t n, uint32_t x){

  return (x >> n);
  
}
```
#### sig0 See Section 3.2 and 4.1.2 for definitions
sig0 rotates rigth by 7 bits by 18 bits and then shr by 3 bits each of these in turn are xor'd.
xor is where there has to be exclusivity of 1 between two binary strings if there is a 1 gets written and a zero if not.
```C
uint32_t sig0(uint32_t x){
  return (rotr(7, x) ^ rotr(18, x) ^ shr(3, x));
}
```
#### sig1 See section 3.2 and 4.1.2 for definitions
sig1 is very similar to sig 0 apart from the degree of bit shifting.
(rotate right 17 bits) xor (rotate right 17 bits) xor (shift right 10 bits)
```C
uint32_t sig1(uint32_t x){
  return (rotr(17, x) ^ rotr(19,x) ^ shr(10, x));
}
```
#### SIG0 See section 4.1.2 for definitions
More rotate right and xor operations.
```C
uint32_t SIG0(uint32_t x){
 return  (rotr(2, x) ^ rotr(13, x) ^ rotr(22, x));
}
```
#### SIG1 See section 4.1.2 for definitions
More rotate right and xor opperations.
```C
uint32_t SIG1(uint32_t x){
  return (rotr(6, x) ^ rotr(11, x) ^ rotr(25, x));
}
```

### Bit selection functions

#### Ch
Ch stands for choose where y, or z gets returned based on the value 
of x being a 1 or a 0.
 Source: https://crypto.stackexchange.com/questions/5358/what-does-maj-and-ch-mean-in-sha-256-algorithm
n.b the "!" negates x for example if x is 1 it becomes a zero and vica versa.
```C
uint32_t Ch(uint32_t x, uint32_t y, uint32_t z){
  return ((x & y) ^ ((!x) & z));
}
```
#### MAJ
Maj stands for majority where the resulting bit is the 
majority of the three input bits x, y, and z
Source : https://crypto.stackexchange.com/questions/5358/what-does-maj-and-ch-mean-in-sha-256-algorithm
```C
uint32_t Maj(uint32_t x, uint32_t y, uint32_t z){
  return ((x & y) ^ (x & z) ^ (y & z));
}
```


# Padding the message
With the SHA-256 algorithm all messages must be a multpile of 512 bit in length.
If the last message block is not 512 bits it must be padded out to 512.
The beginning of the padding starting with a 1 to ensure uniqueness and with the last 8 bytes reserved for writing the size of the file in binary.
Below are coded snippets on how the messages are padded.


#### Unions are used to store each member variable in the same memory location.
This allows for assigning different variable types dynamically from the same memory block.
The Union below can access the msgblock and we can call the different unsigned integers at any time from the same memory location.
This allows us to manipulate the messages blocks as needed.
```C
union msgblock{
  // To access the message block as bytes
  uint8_t e[64];
  // To access the message block as 32-bit integer 
  uint32_t t[16];
  // To access the message block as eight 64-bit integers
  uint64_t s[8];
};
```
#### Reading in a File.
A file can be passed in as a command line argument.
A further error check is used to ensure that a valid file has been passed as an argument.
If an error occurs a message of the error type is displayed within the command line to the user.
```C
// declare A file pointer from cmd input
  FILE* f;
    // open the file from the first argument in the command line
  f = fopen(argv[1], "r");
  //Error check for file input.
  // Adapted from: https://stackoverflow.com/questions/48634880/c-reading-files-passed-as-command-line-argument
  if(f == NULL){
	//Print the error to the user.
    perror("fopen");
    exit(EXIT_FAILURE);
  }
```

#### Checking the file for the need of padding.
Below we have a two conditions.
The first condition checks a flag to see if it has the status of finished and returns zero if it has (terminates).
The second condition test if either PAD0 or PAD1 are true we still need to add padding to the file.
PAD0 starts a new message block with a 1 followed by eight zeros and then fills the rest of the block with all zeros up to the last eight bytes of the file.
PAD1 completes the padded block with a hex representation of the size of the input file.
zeros are added up to the last eight bytes of the file. 
Then the size of the file is added as a hex value to the very end of the final hashed message.
These will be explained further below.
```C
// store the number of bytes read from the file.
  uint64_t nobytes;  
  
  // Loop control variable.
  int i;
  //return S as the flag FINISH if the file has finish reading.
  if(*S == FINISH){
	  
	  return 0;
  }
  
   //Condition to check for PAD0 or PAD1 flags.
  //If either are true there still needs to be additional padding added to the file.  
  if (*S == PAD0 || *S == PAD1) {
	// loop up the the last 8 bytes of the block
    for (i = 0; i < 56; i++){
	  //add all zero bits.
      M->e[i] = 0x00;
    }
	// Add the hex value of the file size to end of the message block. 
    M->s[7] = checkEndian(*nobits);
	//flag S as finished
	*S == FINISH;
 
	if (*S == PAD1){
	  // Add 1 followed by 7 zeros
	  M->e[0] = 0x80;
	  //Enforce the loop to continue for on more iteration to add hashing to the last block.
	  return 1;
	}
 }
```

#### Reading a single message block from the file
The file is parsed one 512 bite chunk at a time.
First we get the size of the message block.

```C
//get the size of the file as bits
    *nobits = *nobits + (nobytes * 8);
```
If the size of the block is less than 56 bytes some padding will be needed to make the file a multiple of 512.
First A 1 is added followed by all zeros up to the last eight bytes.
The last block is set to the size of the file for uniqueness.
Finally the flag is set to finish to signal the loop has completed.
```C

	//get to last eight bytes of the file
    if(nobytes < 56) {
	  
	  //set to 1 followed by 7 zeros
      M->e[nobytes] = 0x80;
	  //loop until the end of the last block
      while (nobytes < 56) {
		//add 1 to nobytes to access next index
        nobytes = nobytes + 1;
		//Set all bytes to zero up to the last eight bytes
		// The size of the file will be the last part of the block
        M->e[nobytes] = 0x00;
      }
	//Truth value for endian
	
		//@todo ensure message is big endian
		//set the last element of M to the size of the file in bits
		//Swap the ordering to big endian
		M->s[7] = checkEndian(*nobits);
	
      //Set enum to finish to exit loop.
      *S = FINISH;
```
#### Padding a file that is exactly a multiple of 512.
Finally if the file happens to be exactly a multiple of 512 in size the file still must be padded.
The same process is followed as above with a1 added to the start of the block with the last eight bytes being reserved for the size of the file.
```C
// Condition to check if there isn't enough room to add padding to the end of the file.
    } else if (nobytes < 64) {
		// States that we need another message block of all zeros
        *S = PAD0;
		// Set the message block e to 1 followed by 7 zero's
        M->e[nobytes] = 0x80;
		// Loop to end of message block to add all zeros
        while(nobytes < 64) {
		  //Access the next index in array.
          nobytes = nobytes + 1;
		  // Set to zero
          M->e[nobytes] = 0x00;
        }
	  // check if end of file reached and the file size is exactly 
	  // a multiple of 64 bytes
      }else if(feof(msgf)){
		// set enum to PAD1.
        *S = PAD1;    
      }
```
## Check the system for big endian
The SHA-256 Algorithm states the final message must be in big endian format.
The below function checks this by having a test variable of 0x01.
Then a check to see if the system displays this value as 10.
```C
uint64_t checkEndian(uint64_t test){
	// Variable to be used check for endian system type.
	int num = 0x01;
	// If the first char is 1 it's little endian
	if (*(char *)&num == 1)
  {
     
	 return swap(test);
	 
  }else {
	return test;
  }
 }
```
If 1 comes first in the string it is a little endian system and the ordering of the bits needs to be reversed.

The below function reverses the ordering of a 64 bit integer.

```C
Adapted from: https://stackoverflow.com/questions/45307516/c-c-code-to-convert-big-endian-to-little-endian
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
```

# Testing the application

To test the application a text file with "abc" as NIST recommendations for test data.
A file containing the ASCII string "abc" results in a 256-bit message digest of BA7816BF 8F01CFEA 414140DE 5DAE2223 B00361A3 96177A9C B410FF61 F20015AD. (source: https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data).
There are three online SHA-256 generators that I used to verify that the output was correct for the file before testing it on the application.


Three different online sha256 generators were used to verify that they both have the same output for the same text file.
The last link in the list below allows for plain text to be input also.
1: https://md5file.com/calculator
2: https://emn178.github.io/online-tools/sha256_checksum.html
3: https://passwordsgenerator.net/sha256-hash-generator/
Results below:

All of the above tests produced the expected digest message of: BA7816BF 8F01CFEA 414140DE 5DAE2223 B00361A3 96177A9C B410FF61 F20015AD

This proves that the file is in the correct format and is suitable for testing the implemented version of the SHA_256 algorithm.

Testing the application results:

#### The resulting output for the test file that contains the string "abc":
b2a49a28 fe1249ed 415a3d18 ee459d58 63b077bf c4c8e0e1 c31df05d c45c65f2.

This result does not match the expected result of the above string

#### The result of an empty file to ensure that something different is being calculated:
Online Calculators:

e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Application output:

7d55ecc0 23def8dc 90db199 ccf368a0 f2f66788 f13217eb ba407df1 29af21cb

The string form the application do not match.


The results from both tests above would indicate that there is a problem somewhere with the application.

### Steps taken to find a solution.

#### Two variables of t within a for loop:

There are two instances of t within a loop. 

The union message block M.t and the loop variable t.

M.t[t] is used inside this loop it may be causing unwanted behaviour.

Action taken:

Message block M.t change to M.q[t]

Result: No change in output.

#### Removing endian converter

Removing endian swap function to see if it causing the issue:

Result:

No change in output

#### Removing endian check

Remove endian check function.

Result:

No change in output.

#### Double check all bit shifting functions MAJ, CH , ROTR, SHR, sig0, sig1, SIG0, SIG1.
Check each of the above functions for typos and position of operators.

Result:

changed input variables of x and n for shr and rotr to match specification.

The algorithm is still producing the incorrect hash vlue


### Conclusion

There is still a problem with the output string of the application and needs to be investigated as to why it is happening.


## Resources used to create this application:

https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data
https://stackoverflow.com/questions/45307516/c-c-code-to-convert-big-endian-to-little-endian
https://crypto.stackexchange.com/questions/5358/what-does-maj-and-ch-mean-in-sha-256-algorithm
https://www.nist.gov/publications/secure-hash-standard
https://www.hackerearth.com/practice/notes/why-a-header-file-such-as-includestdioh-is-used/
https://en.wikibooks.org/wiki/C_Programming/stdint.h
https://stackoverflow.com/questions/8571089/how-can-i-find-endian-ness-of-my-pc-programmatically-using-c 
https://stackoverflow.com/questions/48634880/c-reading-files-passed-as-command-line-argument
https://crypto.stackexchange.com/questions/8636/what-does-message-schedule-mean-in-sha-256
https://crypto.stackexchange.com/questions/5358/what-does-maj-and-ch-mean-in-sha-256-algorithm
https://web.microsoftstream.com/video/db7c03be-5902-4575-9629-34d176ff1366
https://web.microsoftstream.com/video/2a86a2ac-aafb-46e0-a278-a3faa1d13cbf
https://web.microsoftstream.com/video/78dc0c8d-a017-48c8-99da-0714866f35cb
https://web.microsoftstream.com/video/9daaf80b-9c4c-4fdc-9ef6-159e0e4ccc13
https://web.microsoftstream.com/video/200e71ec-1dc1-47a4-9de8-6f58781e3f38
https://web.microsoftstream.com/video/f823809a-d8df-4e12-b243-e1f8ed76b93f
