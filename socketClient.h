#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <map>
#include <thread>

#include "rsa.h"

class SocketClient {
public:
    SocketClient(std::string address, int port)
    {
        m_address = address;
        m_port = port;

        m_server.sin_addr.s_addr = inet_addr(address.c_str());
        m_server.sin_family = AF_INET;
        m_server.sin_port = htons(port);

        m_disconnectListener = nullptr;
        m_connected = false;
        m_threadStopped = false;
        m_packetSize = 4096;
    }

    SocketClient(int socket)
    {
        m_socket = socket;
        m_disconnectListener = nullptr;
        m_connected = true;
        m_threadStopped = false;
        m_packetSize = 4096;
        m_thread = std::thread(staticReceiveThread, this);
        m_thread.detach();
    }

    bool connect()
    {
        m_socket = socket(AF_INET, SOCK_STREAM, 0);

        if (m_socket == -1)
            return false;

        if (::connect(m_socket, (struct sockaddr*)&m_server, sizeof(m_server)) < 0)
            return false;

        m_connected = true;

        m_thread = std::thread(staticReceiveThread, this);
        m_thread.detach();

        return true;
    }

    void disconnect()
    {
        close(m_socket);
        m_connected = false;
        m_threadStopped = true;
    }

    bool send(std::string key, std::string message)
    {
        if (send(key))
            return send(message);

        return false;
    }

    void addListener(std::string key, void (*messageListener)(SocketClient*, std::string))
    {
        m_messageListenerMap[key] = messageListener;
    }

    void setDisconnectListener(void (*disconnectListener)(SocketClient*))
    {
        m_disconnectListener = disconnectListener;
    }

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

    std::map<std::string, void (*)(SocketClient*, std::string)> m_messageListenerMap;

    void (*m_disconnectListener)(SocketClient*);

    void receiveThread()
    {
        std::string key, message;
        int code1, code2;

        while (!m_threadStopped) {
            code1 = receive(key);
            code2 = receive(message);

            if (code1 == 0 || code2 == 0) {
                disconnect();
                if (m_disconnectListener != nullptr) {
                    (*m_disconnectListener)(this);
                }
            } else if (code1 != -1 && code2 != -1) {
                if (m_messageListenerMap[key] != nullptr) {
                    (*m_messageListenerMap[key])(this, message);
                }
            }
        }
    }

    static void staticReceiveThread(void* p)
    {
        SocketClient* client = (SocketClient*)p;
        client->receiveThread();
    }

    int receive(std::string& message)
    {
        uint32_t length;
        int code;
        code = ::recv(m_socket, &length, sizeof(uint32_t), 0);

        if (code != -1 && code != 0) {
            length = ntohl(length);
            char serverReply[length];
            message = "";

            int q = length / m_packetSize;
            int r = length % m_packetSize;

            for (int i = 0; i < q; ++i) {
                code = ::recv(m_socket, serverReply, m_packetSize, 0);

                if (code != -1 && code != 0) {
                    message += std::string(serverReply, m_packetSize);
                } else {
                    return code;
                }
            }

            if (r != 0) {
                char serverReplyRest[r];
                code = ::recv(m_socket, serverReplyRest, r, 0);

                if (code != -1 && code != 0)
                    message += std::string(serverReplyRest, r);
            }
        }

        return code;
    }

    bool send(std::string message)
    {
        uint32_t length = htonl(message.size());

        if (::send(m_socket, &length, sizeof(uint32_t), 0) < 0)
            return false;

        if (::send(m_socket, message.c_str(), message.size(), 0) < 0)
            return false;

        return true;
    }
};