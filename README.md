# SHA-256 in C

This application is an example of implementing the SHA-256 algorithm programmed in C.<br>
This repository holds a fourth year assignment for the module Theory of algorithms at [GMIT](http://gmit.ie) Galway.

Author: [Kevin Gleeson](https://github.com/kevgleeson78)

Fourth year student at: [GMIT](http://gmit.ie) Galway
## Cloning, compiling and running the application.

1: Download [git](https://git-scm.com/downloads) to your machine if not already installed.

1.1: For this project I have used a instance of a Debian system on the google cloud platform.<br>
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
* The first argument is the executible.
* The second command is the file to be passed through the sha256 algorithm.
* You can choose any file you wish in the below example I have use a text file named test.txt with a paragraph of text.
```bash
> /sah256 test.txt
```
6: This will run the application and perform the sha-256 algorithm on test.txt.


# Background of project
The purpose of this project is to demonstrate in the C programming language an implementation of sha-256 encryption algorithm.<br/>
The development of the algorithm was aided by the use of the National Institute of Standards and Technology's [Secure Hash Standard (SHS)](https://www.nist.gov/publications/secure-hash-standard) describing how sha-256 should be implemented and structured.<br/> Below will explain how each phase of the development was completed and how each major function within the script relates to the SHS document's desciption of the algorithm. 


## The SHA-256 Algorithm
The sha-256 algorithm takes message of any length as input and splits the message into message blocks of 64 bytes. Padding is added to the last message block read to ensure uniqueness for the given input. Each of these message blocks have a hashing function performed on them to give an output that is always 256 bits in length and unique to the given input message. The secure hash algorithm sha-256 is a one way function where it is considered infeasable to obtain the input messsage from the 256 bit hashed output. The sections below will describe in more detail on how the algorithm works and how it was implemented in C.




## Implementing SHA-256
The below code snippetts are from the sha256.c file held within this repository.
If you need a copy of the document describing the below algorithm it can be foud [here](https://www.nist.gov/publications/secure-hash-standard).
### Functions Of Application:
This function will be used to hold the main body of the algorithm and will be called in the main function in sha256.c
```C
void sha256();
```
### Contents of sha356 function
#### K constants From section 4.2.2
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
There are eight working variables needed to update the hash values with each itteration of the below loop.
```C
uint32_t a, b, c, d, e, f, g, h;
```
#### Temporary Variables (Section 6.2)
Two temporary variables are lso used in the update of the has values within the below loop(Section 6.2)
```C
  uint32_t T1,T2; 
```
#### Hex Values from (Section 5.3.3)
The following 32-bit words are the inital hash values for the sha256 algorithm.
These values are the first 32-bits  of the fractional parts of the square roots of
the first eight prime numbers.
Each value is assigned to the corresponding eight working variables a, b, c, ... , h as initial values in the first itteration of the algorithm.
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
# Padding to be added....
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
In the below loop the elements from 16 -64 in the W[] array are populated buy running the sig1 and sig0 functions on certain indexeds in the w W array (more details below...).

As descussed above the working variables a,b,c,...,h are initialised to each corresponding element of the h[] array.

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




##Resources used to create this application:



