#include "socketServer.h"

std::vector<SocketClient*> clientsVector;

void forward(std::string key, std::string message, SocketClient* exception)
{
    std::string* _uid = exception->getPrefix();

    std::cout << *_uid << ": ";

    if (exception->getEncryptingStatus())
        message = decrypt(message, exception->getSecretServerKey());

    std::cout << message << std::endl;

    for (auto client : clientsVector) {
        std::string* uid = client->getPrefix();

        if ((*uid) != (*_uid)) {
            if (client->getEncryptingStatus()) {
                client->send(key, encrypt(*_uid + ": " + message, client->getOpenClientKey()));
            } else {
                client->send(key, message);
            }
        }
    }
}

void onMessage(SocketClient* socket, std::string message)
{
    forward("message", message, socket);
}

void onUid(SocketClient* socket, std::string message)
{
    std::stringstream test(message);
    std::string segment;
    std::vector<std::string> seglist;

    while (std::getline(test, segment, ';'))
        seglist.push_back(segment);

    struct key openClientKey;
    openClientKey.e = atoi(seglist[0].c_str());
    openClientKey.m = atoi(seglist[1].c_str());
    socket->setOpenClientKey(openClientKey);
    socket->setEncryptingStatus(true);
}

void onDisconnect(SocketClient* socket)
{
    if (socket->getEncryptingStatus()) {
        forward("message", encrypt("has been disconnected", socket->getOpenServerKey()), socket);
    } else {
        forward("message", "has been disconnected", socket);
    }

    std::string* _uid = socket->getPrefix();

    for (size_t i = 0; i < clientsVector.size(); ++i) {
        std::string* uid = clientsVector[i]->getPrefix();
        if ((*uid) == (*_uid))
            clientsVector.erase(clientsVector.begin() + i);
    }

    delete socket;
}

int main()
{
    uint64_t id = 4857765;
    SocketServer server(8888);

    if (server.start()) {
        std::cout << "server started. listening on port 8888..." << std::endl;
        auto key = generateKeys(primes);
        auto open = key.first;
        auto secret = key.second;

        while (true) {
            int sock = server.accept();

            if (sock != -1) {
                std::cout << "client connected.";

                std::string uid = int_to_hex<uint64_t>(id++);

                std::cout << " ID: " << uid << " has been assined." << std::endl;
                SocketClient* client = new SocketClient(sock);
                client->addListener("message", onMessage);
                client->addListener("Uid", onUid);
                client->setDisconnectListener(onDisconnect);
                client->setPrefix(std::string(uid));
                client->setSecretServerKey(secret);
                client->setOpenServerKey(open);
                client->send("Uid", uid + ";" + std::to_string(open.e) + ";" + std::to_string(open.m));
                clientsVector.push_back(client);
            }
        }
    } else {
        std::cerr << "cannot create server..." << std::endl;
    }

    for (auto x : clientsVector) {
        delete x;
    }

    return 0;
}