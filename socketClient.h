#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <map>
#include <thread>

#include "rsa.h"

class SocketClient {
public:
    // при создании "живого" клиента
    SocketClient(std::string address, int port)
    {
        // записываем куда он подключается
        m_address = address;
        m_port = port;

        m_server.sin_addr.s_addr = inet_addr(address.c_str());
        m_server.sin_family = AF_INET;
        m_server.sin_port = htons(port);

        // инициализируем остальные поля
        m_disconnectListener = nullptr;
        m_connected = false;
        m_threadStopped = false;
        m_packetSize = 4096;
    }
    // при создании локальной записи на сервере
    SocketClient(int socket)
    {
        // инициализируем поля
        m_socket = socket;
        m_disconnectListener = nullptr;
        m_connected = true;
        m_threadStopped = false;
        m_packetSize = 4096;
        // и создаем для пользователя отдельный тред, чтобы он крутился
        // в нем и принимал асинхронно запросы
        m_thread = std::thread(staticReceiveThread, this);
        // join не делает "независимого" треда
        m_thread.detach();
    }

    // "живой" клиент подключаясь
    bool connect()
    {
        // пытается получить сокет
        m_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (m_socket == -1)
            return false;
        // и законнектится к серверу
        if (::connect(m_socket, (struct sockaddr*)&m_server, sizeof(m_server)) < 0)
            return false;
        m_connected = true;

        // и тоже отправляется в отдельный тред ловить ивенты
        m_thread = std::thread(staticReceiveThread, this);
        m_thread.detach();
        return true;
    }

    // при дисконнекте закрываем сокет
    void disconnect()
    {
        close(m_socket);
        m_connected = false;
        m_threadStopped = true;
    }

    // первый слой обертки сокетского сенда
    bool send(std::string key, std::string message)
    {
        // проверяем установлен ли обработчик на соответствующий заголовок key
        if (send(key))
            return send(message);
        return false;
    }

    // добавляем колбеки, каждому "заголовку" соответствует своя "функция
    // обратного вызова"
    void addListener(std::string key,
        void (*messageListener)(SocketClient*, std::string))
    {
        m_messageListenerMap[key] = messageListener;
    }

    // для дисконнета аргументы другие, поэтому колбек свой
    void setDisconnectListener(void (*disconnectListener)(SocketClient*))
    {
        m_disconnectListener = disconnectListener;
    }

    // разные сеттеры и геттеры
    void setPrefix(std::string prefix) { m_prefix = prefix; }

    std::string* getPrefix() { return &m_prefix; }

    void setOpenServerKey(struct key key) { m_openServerKey = key; }

    struct key getOpenServerKey()
    {
        return m_openServerKey;
    }

    void setSecretClientKey(struct key key) { m_secretClientKey = key; }

    struct key getSecretClientKey()
    {
        return m_secretClientKey;
    }

    void setEncryptingStatus(bool status) { m_encrypting = status; }

    bool getEncryptingStatus() { return m_encrypting; }

    void setOpenClientKey(struct key key) { m_openClientKey = key; }

    struct key getOpenClientKey()
    {
        return m_openClientKey;
    }

    void setSecretServerKey(struct key key) { m_secretServerKey = key; }

    struct key getSecretServerKey()
    {
        return m_secretServerKey;
    }

private:
    bool m_encrypting = false;
    struct key m_openServerKey;
    struct key m_secretServerKey;

    struct key m_openClientKey;
    struct key m_secretClientKey;

    std::string m_prefix;

    struct sockaddr_in m_server;
    std::string m_address;
    int m_port;
    int m_socket;
    bool m_connected;
    bool m_threadStopped;
    int m_packetSize;
    std::thread m_thread;

    // ассоциативный контейнер (ключ-значение) для колбеков, ключи это строки
    // а знаечния -- указатели на функции
    std::map<std::string, void (*)(SocketClient*, std::string)>
        m_messageListenerMap;

    // для дисконнекта, опять же, аргументы другие, поэтому он отдельно
    void (*m_disconnectListener)(SocketClient*);

    // первый слой обертки ресива
    void receiveThread()
    {
        std::string key, message;
        int code1, code2;
        // пока тред существует
        while (!m_threadStopped) {
            // считаем "заголовок"
            code1 = receive(key);
            // и "тело" сообщения
            code2 = receive(message);
            // если коды нулевые, то это значит дисконнект
            if (code1 == 0 || code2 == 0) {
                disconnect();
                // при установленном коллбеке вызываем его
                if (m_disconnectListener != nullptr) {
                    // у нас указатель на функцию, поэтому чтоб вызвать
                    // саму функцию его надо разыменовать
                    (*m_disconnectListener)(this);
                }
                // если же и заголовок и тело в порядке
            } else if (code1 != -1 && code2 != -1) {
                // и для соответствующего заголовка установлен колбек
                if (m_messageListenerMap[key] != nullptr) {
                    // то вызовем его
                    (*m_messageListenerMap[key])(this, message);
                }
            }
        }
    }

    // этот метод исполняется в треде. сделан статичным чтобы
    // не делать френдом, т.к. ресивТред приватный метод и на момент
    // вызова инстанса класса может еще не существовать, значит не будет
    // и этого метода, не будь он статичным
    static void staticReceiveThread(void* p)
    {
        SocketClient* client = (SocketClient*)p;
        client->receiveThread();
    }

    // вторая обертка для ресива
    int receive(std::string& message)
    {
        uint32_t length;
        int code;
        // попробуем прочитать пришел ли размер сообщения сокетовским ресивом
        code = ::recv(m_socket, &length, sizeof(uint32_t), 0);
        // если пришло что-то вразумительное
        if (code != -1 && code != 0) {
            // перевернем пришедшие байты
            length = ntohl(length);
            // создадим с-стайл строку
            char serverReply[length];
            // и строку для сообщения
            message = "";

            // чтоб каждый чар с сокета не снимать, сделаем это почанково
            // посчитаем сколько чанков выбранного нами размера пакета есть
            int q = length / m_packetSize;
            // и сколько "лишнего"
            int r = length % m_packetSize;

            // будем считывать настоящим ресивом чанки
            for (int i = 0; i < q; ++i) {
                code = ::recv(m_socket, serverReply, m_packetSize, 0);
                // при корректности считанного
                if (code != -1 && code != 0) {
                    // добавлять его к нашей заготовке строки
                    message += std::string(serverReply, m_packetSize);
                } else {
                    return code;
                }
            }

            // и сделаем это отдельно для "хвоста"
            if (r != 0) {
                char serverReplyRest[r];
                code = ::recv(m_socket, serverReplyRest, r, 0);
                if (code != -1 && code != 0)
                    message += std::string(serverReplyRest, r);
            }
        }
        return code;
    }

    // вторая обертка для сенда
    bool send(std::string message)
    {
        // перевернем длину размера сообщения
        uint32_t length = htonl(message.size());
        // попробуем отправить длину
        if (::send(m_socket, &length, sizeof(uint32_t), 0) < 0)
            return false;
        // а затем и само сообщение
        if (::send(m_socket, message.c_str(), message.size(), 0) < 0)
            return false;
        return true;
    }
};