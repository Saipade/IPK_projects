# IPK 1. project - server

### Brief description

Implementation of the 1. IPK project -- simple HTTP server which is capable of providing basic system information (cpu name, hostname, cpu load). 

### Building the program

make all -- build
make zip -- make archive

executable name -- hinfosvc

### Usage

# Execute: ./hinfosvc *port number*

# Possible requests:
GET http://localhost:*port number*/hostname
GET http://localhost:*port number*/cpu-name
GET http://localhost:*port number*/load

# Examples
```
$ 1. ./hinfosvc 12345 & GET http://localhost:12345/hostname & GET http://localhost:12345/cpu-name
$ 2. ./hinfosvc 12345 & GET http://localhost:12345/load
$ GET http://localhost:12345/load
$ 3. ./hinfosvc 12345 &
$ GET http://localhost:12345/cpu-name
```

# Killing server

CTRL+C

