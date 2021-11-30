#include <iomanip>
#include <random>
#include <sstream>

#include "primes.h"

// ключ это два числа -- экспонента и модуль
struct key {
    uint64_t e;
    uint64_t m;
};

// расширенный алгоритм Евклида
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

// Нахождение обратного числа по модулю
int64_t invertByMod(int64_t a, int64_t m)
{
    int64_t x, y;
    gcdExt(a, m, x, y);
    x = (x % m + m) % m;
    return x;
}

// почему-то было лень перемножить через ctrl+c ctrl+v...
uint64_t sqr(uint64_t x) { return x * x; }

// быстрое возведение в степень по модулю, чтобы делать меньше умножений,
// то есть если степень 0, то сразу выводим 1, если не 0
// и нечетная, то умножаем основание на то что осталось,
// а если четная, то умножаем число с таким же основанием, но вдвое меньшим
// показателем на само себя
uint64_t binPow(uint64_t a, uint64_t e, uint64_t mod = __LONG_LONG_MAX__)
{
    return e == 0 ? 1
                  : (e & 1 ? a * binPow(a, e - 1, mod) % mod
                           : sqr(binPow(a, e / 2, mod)) % mod);
}

// для генерации ключей по двум простым числам
std::pair<key, key> generateKeys(uint64_t p, uint64_t q)
{
    // значение функции эйлера от их произведения
    uint64_t phi = (p - 1) * (q - 1);
    // открытый и закрытый модули (просто модуль)
    uint64_t n = p * q;
    // исторически сложилось брать для открытой экспоненты простые числа ферма
    uint64_t e = 65537;
    // секретную экспоненту вычисляем как обратную к открытой по модулю значения
    // функции эйлера от произведения данных двух простых
    uint64_t d = invertByMod(e, phi);
    return { { e, n }, { d, n } };
}

// нужно посчитать, а какого размера блок мы можем зашифровать нашим ключом
// (меньше модуля)
uint8_t getChunkSize(key k) { return 32 - __builtin_clz(k.m); }

// мы работаем с числами, возводя их в степени по модулям, поэтому
// сообщение надо заресайзить под соотвующий ключу размер блока
std::vector<uint64_t> resize(const std::vector<uint64_t>& data, uint8_t in_size,
    uint8_t out_size)
{
    std::vector<uint64_t> res;
    uint8_t done = 0;
    uint64_t cur = 0;
    for (uint64_t byte : data)
        // мы сообщаем, сколько бит данных есть и
        for (uint8_t i = 0; i < in_size; i++) {
            // каждый битик, слева напарво, переносим в cur, сдвигая cur.
            cur = (cur << 1) + (((uint64_t)byte & (1 << (uint64_t)(in_size - 1 - i))) != 0);
            // cur и done обнуляются только по условию, т.е. они "сквозные" для
            // range-based цикла снаружи, этим и обеспечивается ресайз
            done++;
            // как только нужно число битов перенесено
            if (done == out_size) {
                done = 0;
                // заносим ресайзнутый байт (т.е. в нем только какая-то
                // подпоследовательность из последовательности бит сообщения,
                // удовлетворяющая условию "проходит по размеру")
                res.push_back(cur);
                cur = 0;
            }
        }
    // Дополнение нулями, опять же, из-за того что cur и done сквозные
    // вполне вероятно окажется что по выходе из циклов в cur будет неправильный
    // сдвиг, т.е. последний cur не будет непрерывно продолжать предыдущий cur, а
    // значит его надо сдвинуть, то есть дополнить нулями справа
    if (done != 0)
        res.push_back(cur << (uint64_t)(out_size - done));
    return res;
}

// символ это число
// процесс что шифровация что дешифрования один и тот же -- возведение в нужную
// степень по нужному модулю
std::vector<uint8_t> processBytes(const std::vector<uint8_t>& data, key k,
    bool encrypt)
{
    // каждый символ(число) представим как uint64_t
    std::vector<uint64_t> data_64(data.size());
    for (int i = 0; i < data.size(); i++)
        data_64[i] = (uint64_t)data[i];
    // ресайзим под размер блока (разбиваем на блоки)
    std::vector<uint64_t> resized_data = resize(data_64, 8,
        getChunkSize(k) - encrypt); // Если мы шифруем, то размер блока
        // K-1 иначе K
    std::vector<uint64_t> encrypted_data(resized_data.size());

    // шифруем (возводим в степень ключа и берем по модулю модуля)
    for (int i = 0; i < resized_data.size(); i++)
        // каждый блок
        encrypted_data[i] = binPow(resized_data[i], k.e, k.m);

    // ресайзим обратное, т.е. соединяем блоки
    std::vector<uint64_t> result_64 = resize(encrypted_data, getChunkSize(k) - !encrypt,
        8); // если зашифровали, то собирать надо из блоков K, если
        // расшифровали, то из K-1 (т.к. был K-1 в первом случае и K
        // во втором)

    // делаем, по сути, снова строку
    std::vector<uint8_t> result(result_64.size());
    for (int i = 0; i < result_64.size(); i++)
        result[i] = (uint8_t)result_64[i];
    return result;
}

// симметричные функции для шифрации и дешефрации,
// чтобы decrypt(encrypt(msg, open), close) выдало msg
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

// красивый вид числа в виде хекса
template <typename T>
std::string int_to_hex(T i)
{
    std::stringstream stream;
    stream << std::hex << i;
    return stream.str();
}

// генерация пары ключей по массиву простых
std::pair<key, key> generateKeys(std::vector<uint64_t>& primes)
{
    // будем брать пару раномерно распределенных чисел,
    // соответствующих индексам чисел в массиве
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, primes.size() - 1);
    size_t i = dis(gen);
    size_t j = 0;
    // разных чисел
    do {
        j = dis(gen);
    } while (i == j);
    // сгенерируем по полученным числам уже наш ключ
    return generateKeys(primes[i], primes[j]);
}
