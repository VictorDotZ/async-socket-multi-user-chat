#include "socketClient.h"

// колбек для получения сообщений, срабатывает когда приходит сообщение
void onMessage(SocketClient* sender, std::string message)
{
    // если шифрование включено, то пришедшее зашифрованное сообщение
    // надо предварительно расшифровать приватным ключом клиента
    if (sender->getEncryptingStatus())
        message = decrypt(message, sender->getSecretClientKey());
    std::cout << message << std::endl;
}

// колбек для инициализации(авторизации) клиента
void onUid(SocketClient* sender, std::string message)
{
    // сервер присылает сериализованные данные,
    std::stringstream test(message);
    std::string segment;
    std::vector<std::string> seglist;

    // их необходимо десериализовать, сепаратор ; и используем
    // возможности с++, создавая "фейковый" поток, в который закидываем строку
    while (std::getline(test, segment, ';'))
        seglist.push_back(segment);

    // в первом блоке приходит айди клиента, его "ник", выданный сервером,
    // полезно знать как наши сообщения будут видеть другие пользователи
    sender->setPrefix(seglist[0]);

    // в двух других блоках приходят открыте экспонента и модуль
    // открытого ключа сервера поэтому считаем их
    struct key openServerKey;
    openServerKey.e = atoi(seglist[1].c_str());
    openServerKey.m = atoi(seglist[2].c_str());

    // и сохраним
    sender->setOpenServerKey(openServerKey);

    // а пользователю сообщим его айди для интереса
    std::cout << "your id: " << seglist[0] << std::endl;
}

// колбек для принудительного дисконекта, т.к. если пользователь
// самостоятельно отключается, то он об этом, как правило, знает
void onDisconnect(SocketClient* socket)
{
    std::cout << "you (" << *socket->getPrefix()
              << ") have been disconnected" << std::endl;
}

int main()
{
    // создаем клиента и указываем "направление" до сервера
    SocketClient client("127.0.0.1", 8888);

    // вешаем колбеки на события message Uid и дисконект
    client.addListener("message", onMessage);
    client.addListener("Uid", onUid);
    client.setDisconnectListener(onDisconnect);

    // генерируем пару ключей клиента
    auto key = generateKeys(primes);

    // сохраняем наш приватный ключ
    client.setSecretClientKey(key.second);

    // пробуем подключиться к серверу
    if (!client.connect()) {
        std::cout << "cannot connect to server" << std::endl;
        return 0;
    }
    std::cout << "connected to server" << std::endl;

    // при коннекте сервер посылает нам сообщение с "заголовком"
    // Uid , которое мы обработаем функцией выше, а мы ему пошлем
    // свои данные -- наш открытый ключ, предварительно его сериализовав
    if (!client.send("Uid", std::to_string(key.first.e) + ';' + std::to_string(key.first.m))) {
        std::cout << "failed to send message" << std::endl;
        return 0;
    }

    // после этого пометим, что наше общение идет в зашифрованном режиме
    client.setEncryptingStatus(true);
    std::string line;

    // и начнем непосредственно работу
    while (true) {
        // будем получать сообщение из консоли
        getline(std::cin, line);

        // шифровать его, если установлен соответствующий флаг
        // публичным ключом сервера
        if (client.getEncryptingStatus())
            line = encrypt(line, client.getOpenServerKey());

        // и пытаться отправить
        if (!client.send("message", line)) {
            std::cout << "failed to send message" << std::endl;
            return 0;
        }
    }

    client.disconnect();

    return 0;
}
