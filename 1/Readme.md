# IPK 1. project - server

## Brief description

Implementation of the 1. IPK project -- simple HTTP server which is capable of providing basic system information such as CPU name, hostname and CPU load. 

## Building the program

- to build: make all

- to make archive: make zip

- executable name - hinfosvc

## Usage

### Execute: 
- ./hinfosvc **port number**

### Possible requests:
- GET http&#x200B;://localhost:**port number**/hostname
- GET http&#x200B;://localhost:**port number**/cpu-name
- GET http&#x200B;://localhost:**port number**/load

### Examples
```
1. $ ./hinfosvc 12345 & GET http://localhost:12345/hostname & GET http://localhost:12345/cpu-name
2. $ ./hinfosvc 12345 & GET http://localhost:12345/load
   $ GET http://localhost:12345/load
3. $ ./hinfosvc 12345 &
   $ GET http://localhost:12345/cpu-name
```

### Killing the server

- CTRL+C

## Author

- Maksim Tikhonov xtikho00

