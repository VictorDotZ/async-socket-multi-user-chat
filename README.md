# async-socket-multi-user-chat
Multi-user chat on sockets with threads for async working.

## Compilation
Server:
```bash
g++ -o server.out server.cpp -pthread
```

Client:
```bash
g++ -o client.out client.cpp -pthread
```

## Usage
Type these commands in different terminal instances. Use the first one for the server and the other ones for clients.

Server:
```bash
./server.out
```

Client:
```bash
./client.out
```


---
TODO: rewrite for makefile usage possibility (transfer definitions into separate files)

---
Thanks to https://github.com/OmarAflak/Async-Socket for async sockets.

Thanks to https://cpp.mazurok.com/tinyrsa/ for tiny RSA algorithm.