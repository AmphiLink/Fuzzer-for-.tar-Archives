# CSS-Project
[![Linux](https://img.shields.io/badge/Linux-compatible-purple?&logo=linux&logoColor=darkgrey)](https://www.linux.org/pages/download/)
[![MacOS](https://img.shields.io/badge/MacOS-compatible-purple?&logo=apple&logoColor=darkgrey)](https://support.apple.com/en-us/102662)  µ

[![C](https://img.shields.io/badge/-17-blue?&logo=C&logoColor=darkgrey)](https://installc.org/)

## Authors 
1. Esteban Bernagou - 000616080
2. Edwyn Eben - 000616809

## Description 
This project aims to fuze an Archive TAR POSIX 1003.1-1990.
The description of those headers is available at:  
https://www.gnu.org/software/tar/manual/html_node/Standard.html.

## Prerequisites
You must have C99+ installed on your machine.  
Click on the shield above to install it.

## How to get Started
First clone the repo and navigate to the source of the project using cd.  
Then compile the source code to an executable.  
Open a terminal and type this command:
```
make
```
Then pass the path of your extractor as an argument to the executable like this:
```
./fuzzer "./extractor_x86_64"
```
If you are have an Apple silicon chip use this extractor:
```
./fuzzer "./extractor_apple"
```