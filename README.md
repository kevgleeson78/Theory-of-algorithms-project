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
If you need a copy of the document describing the below algorithm it can be foud [here](https://www.nist.gov/publications/secure-hash-standard).








##Resources used to create this application:



