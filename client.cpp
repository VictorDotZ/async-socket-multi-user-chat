#include "socketClient.h"

void onMessage(SocketClient* sender, std::string message)
{
    if (sender->getEncryptingStatus())
        message = decrypt(message, sender->getSecretClientKey());

    std::cout << message << std::endl;
}

void onUid(SocketClient* sender, std::string message)
{
    std::stringstream test(message);
    std::string segment;
    std::vector<std::string> seglist;

    while (std::getline(test, segment, ';'))
        seglist.push_back(segment);

    sender->setPrefix(seglist[0]);

    struct key openServerKey;
    openServerKey.e = atoi(seglist[1].c_str());
    openServerKey.m = atoi(seglist[2].c_str());

    sender->setOpenServerKey(openServerKey);

    std::cout << "your id: " << seglist[0] << std::endl;
}

void onDisconnect(SocketClient* socket)
{
    std::cout << "you (" << *socket->getPrefix() << ") have been disconnected" << std::endl;
}

int main()
{
    SocketClient client("127.0.0.1", 8888);

    client.addListener("message", onMessage);
    client.addListener("Uid", onUid);
    client.setDisconnectListener(onDisconnect);

    auto key = generateKeys(primes);

    client.setSecretClientKey(key.second);

    if (!client.connect()) {
        std::cout << "cannot connect to server" << std::endl;

        return 0;
    }

    std::cout << "connected to server" << std::endl;

    if (!client.send("Uid", std::to_string(key.first.e) + ';' + std::to_string(key.first.m))) {
        std::cout << "failed to send message" << std::endl;

        return 0;
    }

    client.setEncryptingStatus(true);
    std::string line;

    while (true) {
        getline(std::cin, line);

        if (client.getEncryptingStatus())
            line = encrypt(line, client.getOpenServerKey());

        if (!client.send("message", line)) {
            std::cout << "failed to send message" << std::endl;

            return 0;
        }
    }

    client.disconnect();

    return 0;
}
