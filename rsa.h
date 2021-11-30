#include <iomanip>
#include <random>
#include <sstream>

#include "primes.h"

struct key {
    uint64_t e;
    uint64_t m;
};

int64_t gcdExt(int64_t a, int64_t b, int64_t& x, int64_t& y)
{
    int64_t q, r, x1, x2, y1, y2, d;

    if (b == 0) {
        d = a, x = 1, y = 0;

        return d;
    }

    x2 = 1, x1 = 0, y2 = 0, y1 = 1;

    while (b > 0) {
        q = a / b, r = a - q * b;
        x = x2 - q * x1, y = y2 - q * y1;
        a = b, b = r;
        x2 = x1, x1 = x, y2 = y1, y1 = y;
    }

    d = a, x = x2, y = y2;

    return d;
}

int64_t invertByMod(int64_t a, int64_t m)
{
    int64_t x, y;
    gcdExt(a, m, x, y);
    x = (x % m + m) % m;

    return x;
}

uint64_t sqr(uint64_t x)
{
    return x * x;
}

uint64_t binPow(uint64_t a, uint64_t e, uint64_t mod = __LONG_LONG_MAX__)
{
    return e == 0 ? 1
                  : (e & 1 ? a * binPow(a, e - 1, mod) % mod
                           : sqr(binPow(a, e / 2, mod)) % mod);
}

std::pair<key, key> generateKeys(uint64_t p, uint64_t q)
{
    uint64_t phi = (p - 1) * (q - 1);
    uint64_t n = p * q;
    uint64_t e = 65537;
    uint64_t d = invertByMod(e, phi);

    return { { e, n }, { d, n } };
}

uint8_t getChunkSize(key k)
{
    return 32 - __builtin_clz(k.m);
}

std::vector<uint64_t> resize(const std::vector<uint64_t>& data, uint8_t in_size,
    uint8_t out_size)
{
    std::vector<uint64_t> res;
    uint8_t done = 0;
    uint64_t cur = 0;

    for (uint64_t byte : data)
        for (uint8_t i = 0; i < in_size; i++) {
            cur = (cur << 1) + (((uint64_t)byte & (1 << (uint64_t)(in_size - 1 - i))) != 0);
            done++;

            if (done == out_size) {
                done = 0;
                res.push_back(cur);
                cur = 0;
            }
        }

    if (done != 0)
        res.push_back(cur << (uint64_t)(out_size - done));

    return res;
}

std::vector<uint8_t> processBytes(const std::vector<uint8_t>& data, key k, bool encrypt)
{
    std::vector<uint64_t> data_64(data.size());
    for (int i = 0; i < data.size(); i++)
        data_64[i] = (uint64_t)data[i];

    std::vector<uint64_t> resized_data = resize(data_64, 8, getChunkSize(k) - encrypt);
    std::vector<uint64_t> encrypted_data(resized_data.size());

    for (int i = 0; i < resized_data.size(); i++)
        encrypted_data[i] = binPow(resized_data[i], k.e, k.m);

    std::vector<uint64_t> result_64 = resize(encrypted_data, getChunkSize(k) - !encrypt, 8);

    std::vector<uint8_t> result(result_64.size());
    for (int i = 0; i < result_64.size(); i++)
        result[i] = (uint8_t)result_64[i];
    return result;
}

std::string encrypt(const std::string& msg, const struct key& key)
{
    std::vector<uint8_t> vec(msg.begin(), msg.end());
    std::vector<uint8_t> res = processBytes(vec, key, true);

    return std::string(res.begin(), res.end());
}

std::string decrypt(const std::string& msg, const struct key& key)
{
    std::vector<uint8_t> vec(msg.begin(), msg.end());
    std::vector<uint8_t> res = processBytes(vec, key, false);

    return std::string(res.begin(), res.end());
}

template <typename T>
std::string int_to_hex(T i)
{
    std::stringstream stream;
    stream << std::hex << i;
    return stream.str();
}

std::pair<key, key> generateKeys(std::vector<uint64_t>& primes)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, primes.size() - 1);
    size_t i = dis(gen);
    size_t j = 0;

    do {
        j = dis(gen);
    } while (i == j);

    return generateKeys(primes[i], primes[j]);
}
