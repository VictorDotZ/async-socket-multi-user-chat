#include "socketServer.h"

// создадим "базу" клиентов на сервере
std::vector<SocketClient*> clientsVector;

// рассылка сообщений
void forward(std::string key, std::string message, SocketClient* exception)
{
    // прочтем айди отправившего сообщение клиента
    std::string* _uid = exception->getPrefix();

    // и заодно будем вести на сервере лог чата, выведем кто отправил сообщение
    std::cout << *_uid << ": ";

    // если общение с клиентом в шифрованнов режиме, то сообщение надо
    // расшифровать закрытым ключом сервера
    if (exception->getEncryptingStatus())
        message = decrypt(message, exception->getSecretServerKey());

    // напечатать что же написал клиент
    std::cout << message << std::endl;

    // пройтись по всем клиентам в нашей "базе"
    for (auto client : clientsVector) {
        std::string* uid = client->getPrefix();

        // и если это не тот же самый клиент, который сообщение и отправил
        if ((*uid) != (*_uid)) {
            // то при установленном флаге на шифрованный обмен сообщений
            if (client->getEncryptingStatus()) {
                // зашифровать его соответствующим текущему клиенту его открытым ключом
                // и отправить
                client->send(
                    key, encrypt(*_uid + ": " + message, client->getOpenClientKey()));
            } else {
                // ну или просто отправить
                client->send(key, message);
            }
        }
    }
}

// колбек, который будет вызываться при получении сервером сообщения
void onMessage(SocketClient* socket, std::string message)
{
    // по сути просто обертка для единообразия, прокидывающая всё дальше
    forward("message", message, socket);
}
// колбек, который будет вызываться когда клиент пришлет свои учетные данные
void onUid(SocketClient* socket, std::string message)
{
    // аналогичный трюк как на клиентской части для десереализации
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

// колбек для дисконекта клиента
void onDisconnect(SocketClient* socket)
{
    // когда клиент дисконектится он посылает на сервер информацию об этом
    // и мы сообщаем остальным клиентам об этом
    if (socket->getEncryptingStatus()) {
        forward("message",
            encrypt("has been disconnected", socket->getOpenServerKey()),
            socket);
    } else {
        forward("message", "has been disconnected", socket);
    }
    // посмотрим айди пользователя, который дисконектнулся
    std::string* _uid = socket->getPrefix();
    for (size_t i = 0; i < clientsVector.size(); ++i) {
        std::string* uid = clientsVector[i]->getPrefix();
        // и удалим его из нашей "базы"
        if ((*uid) == (*_uid))
            clientsVector.erase(clientsVector.begin() + i);
    }
    delete socket;
}

int main()
{
    // просто число чтоб hex'ы айдишников были интереснее чем 0, 1, 2 и т.д.
    uint64_t id = 4857765;
    // создадим сервер
    SocketServer server(8888);
    // попробуем его запустить
    if (server.start()) {
        std::cout << "server started. listening on port 8888..." << std::endl;
        // сгенерируем пару ключей
        auto key = generateKeys(primes);
        auto open = key.first;
        auto secret = key.second;
        // начнем саму работу
        while (true) {
            // посмотрим стучится ли кто к нам
            int sock = server.accept();

            // если стучится то примем клиента
            if (sock != -1) {
                std::cout << "client connected.";

                // присвоим ему айди в "красивой" форме хекса
                std::string uid = int_to_hex<uint64_t>(id++);

                std::cout << " ID: " << uid << " has been assined." << std::endl;
                // создадим на сервере запись о нем
                SocketClient* client = new SocketClient(sock);
                // повесим на него колбеки
                client->addListener("message", onMessage);
                client->addListener("Uid", onUid);
                client->setDisconnectListener(onDisconnect);
                // установим его айди
                client->setPrefix(std::string(uid));
                // установим секретный ключ сервера, т.к. запись не покидает пределов
                // сервера
                client->setSecretServerKey(secret);
                // открытый, чтобы было чем шифровать сообщения
                client->setOpenServerKey(open);
                // и отправим этот открытый ключ в сериализованном виде
                client->send("Uid", uid + ";" + std::to_string(open.e) + ";" + std::to_string(open.m));
                // после чего внесем готового нового пользователя в "базу"
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