#include "socketClient.h"

class SocketServer {
public:
    // при создании сервера
    SocketServer(int port)
    {
        // записываем на каком порте его создаем
        m_port = port;
        // что за вид адресов используем
        m_server.sin_family = AF_INET;
        // нулем инициализируем адрес
        m_server.sin_addr.s_addr = INADDR_ANY;
        // записываем порт, меняя порядок байтов
        m_server.sin_port = htons(port);
    }

    // при запуске сервера
    bool start()
    {
        // просим выделить сокет
        m_socket = ::socket(AF_INET, SOCK_STREAM, 0);
        // если получилось
        if (m_socket != -1) {
            // пробуем связать сокет с заранее подготовленным приватным полем
            if (::bind(m_socket, (struct sockaddr*)&m_server, sizeof(m_server)) >= 0) {
                // и начинаем слушать не стучиться ли кто
                ::listen(m_socket, 5);
                return true;
            }
        }
        return false;
    }
    // если кто стучиться
    int accept()
    {
        int c = sizeof(struct sockaddr_in);
        struct sockaddr_in client;
        // пробуем принять клиента
        int clientSock = ::accept(m_socket, (struct sockaddr*)&client, (socklen_t*)&c);
        if (clientSock < 0) {
            return -1;
        }
        return clientSock;
    }

private:
    int m_port;
    int m_socket;
    struct sockaddr_in m_server;
};