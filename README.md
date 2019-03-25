# SHA256 in C

This application is an example of implementing the SHA256 algorithm programmed in C.<br>
This repository holds a fourth year assignment for the module Theory of algorithms at [GMIT](http://gmit.ie) Galway.

Author: [Kevin Gleeson](https://github.com/kevgleeson78)

Fourth year student at: [GMIT](http://gmit.ie) Galway
## Cloning, compiling and running the application.

1: Download [git](https://git-scm.com/downloads) to your machine if not already installed.

1.1: For this project I have used a instance of a Debian system on the google cloud platform.<br>
This is used to compile and run the various files held within this repository. Please see below for further instruction on how to compile the files needed.

2: Open ssh command prompt within the Google cloud console and continue to step three below.

 
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
6: This will run the application and perform the sha256 algorithm on test.txt.


# Application Functionality 


## Explaination of major functions


##Resources used to create this app:



