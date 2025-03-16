#include "twofish.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h> 
#include <dirent.h>
#include <unistd.h> 



/***************************************************************************************
 *                   Функции add_padding и is_valid_padding
 * 
 * Функция add_padding нужна, собственно, для паддинга - дополнения блока до 16 байт, в
 * случае, если его длина меньше. Остальные значения заполняются нулями. Для проверки
 * корректности паддинга нужна функция add_padding. Она берёт значение последнего байта
 * и сравнивает его с размером блока (больше размера блока или 0 -> ошибка). В случае
 * ошибки возвращает 0 (ошибка выводится в main).
 * 
 **************************************************************************************/

void add_padding(BYTE *block, size_t data_len, size_t block_size) {
    BYTE pad_value = block_size - data_len;
    for (size_t i = data_len; i < block_size; i++) {
        block[i] = pad_value;
    }
}


int is_valid_padding(BYTE *block, size_t block_size) {
    BYTE pad_value = block[block_size - 1];
    if (pad_value > block_size || pad_value == 0) {
        return 0; // Некорректный padding
    }
    for (size_t i = block_size - pad_value; i < block_size; i++) {
        if (block[i] != pad_value) return 0;
    }
    return 1;
}


// Функция для перевода строки в массив из 16 байтов (ключ в виде hex)
void parse_key(const char *key_str, BYTE *key) {
    for (int i = 0; i < 16; i++) {
        sscanf(key_str + 2 * i, "%2hhx", &key[i]); // Считываем по 2 символа как hex
    }
}


// Возвращает исходный размер данных (удаляет паддинг)
size_t remove_padding(BYTE *block, size_t block_size) {
    BYTE pad_value = block[block_size - 1];
    return block_size - pad_value;  
}


// Макросы для циклического сдвига 32-битных целых чисел
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))      // Влево
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))      // Вправо



/***************************************************************************************
 *                                    Функция h
 * 
 * В цикле, длинной с количество кодключей k, выполняется операция XOR для текущего
 * значения и последовательного подключа. Учитывая вовлечённость текущего result в 
 * для каждого последующего XOR, функция h обеспечивает отличное "волновое изменение".
 * 
 **************************************************************************************/

unsigned long long h(UINT x, UINT *keys, int k) {
    unsigned long long result = x;
    for (int i = 0; i < k; i++) {
        result ^= (keys[i] + result);
    }
    return result;
}



/***************************************************************************************
 *                              Функция TwoFish_init
 * 
 * Данная функция реализует подготовительную часть алггоритма шифрования Twofish. Состоит она
 * из нескольких этапов. На первом этапе происходит проверка длины ключа (согласно требованиям
 * AES, длина ключа Twofish составляет 128, 192 или 256 бит). Если длина ключа недостаточна,
 * то ключ дополняется нулями. В зависимости от размера ключа, определяется сколько слов
 * (32-битных блоков) будет в ключе. Создаётся врмененный ключ. Следующий этап функции
 * это заполнение масивов Me (чётные индексы) и Mo (нечётные индексы), выполняется сдвиг
 * по байтам. Далее, с использованием временного ключа и матрицы RS генерируются S-боксы.
 * Крайний этап функции - генерация 40 подключей длиной 32 бита. 4+4 ключа нужны для нача-
 * льного и конечного отбеливания, а 32 других используются в сети Фейстеля, по 2 на раунд.
 *  
 **************************************************************************************/

void TwoFish_init(TwoFish *tf, BYTE *key, size_t length) {

    // N - есть количество 32-битных блоков
    short N = 0;
    if (length > 192) {
        N = 256;
    } else if ((length > 128) && (length <= 192)) {
        N = 192;
    } else N = 128;

    // Выделение памяти для временного ключа
    BYTE *temp_key = (BYTE *)malloc(N);
    for (int i = 0; i < N; i++) {
        temp_key[i] = (i < length) ? key[i] : 0;
    }

    tf->k = N / 64;

    // Выделение памяти под массивы Me (чётный) и Mo (нечётный)
    UINT *Me = (UINT *)malloc(tf->k * sizeof(UINT));
    UINT *Mo = (UINT *)malloc(tf->k * sizeof(UINT));

    BYTE RS[4][8] = {
        {0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E},
        {0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5},
        {0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19},
        {0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03}
    };

    //Заполнение Me и Mo
    for (int c1 = 0, c2 = 0, i = 0; i < 2 * tf->k; i++) {
        if (i % 2 == 0) {
            Me[c1] = 0;
            for (int j = 4 * i, shift = 3; j < 4 * (i + 1); j++, shift--) {
                Me[c1] += (temp_key[j] << (shift * 8));
            }
            c1++;
        } else {
            Mo[c2] = 0;
            for (int j = 4 * i, shift = 3; j < 4 * (i + 1); j++, shift--) {
                Mo[c2] = temp_key[j] << (shift * 8);
            }
            c2++;
        }
    }

    //Генерация S-боксов
    tf->SBox = (UINT *)malloc(tf->k * sizeof(UINT));
    for (int i = 0; i < tf->k; i++) {
        tf->SBox[tf->k - 1 - i] = 0;
        for (int j = 0; j < 4; j++) {
            UINT v = 0;
            for (int t = 0; t < 8; t++) {
                v += RS[j][t] * temp_key[8 * i + t];
            }
            tf->SBox[tf->k - 1 - i] += (v * (1 << (8 * j)));
        }
    }

    //Генерация подключей
    UINT ro = (1 << 24) + (1 << 16) + (1 << 8) + 1;
    for (int i = 0; i < 20; i++) {
        unsigned long long A = h(2 * i * ro, Me, tf->k);
        unsigned long long B = h((2 * i + 1) * ro, Mo, tf->k);
        B = ROL(B, 8);
        tf->keys[2 * i] = (A + B) & 0xFFFFFFFF;
        tf->keys[2 * i + 1] = ROL(((A + 2 * B) & 0xFFFFFFFF), 9);
    }

    free(Me);
    free(Mo);
    free(temp_key);
}


// "Чистильщик"
void TwoFish_cleanup(TwoFish *tf) {
    free(tf->SBox);
}



/***************************************************************************************
 *                               Функция TwoFish_encrypt
 * 
 * Данная функция выполняет процесс непосредственного шифрования данных. Входные 16 байт
 * (вектор plain) дробится на на 4 32-битных целых числа (A, B, C, D), каждое из которых
 * делится ещё на 4 равные части (итого у нас 16 различных частей, размером в 1 байт).
 * После разбиения, для кажого из 4 32-битных значений выполняется XOR с подключами (оно
 * же "начальное отбеливание"). Затем запускается сеть Фейстеля: на каждом раунде для
 * переменной A вызывается хеш-функция h, S-бокс и размер слова. Для переменной B перед
 * аналогичным применением функции h, выполняется циклический сдвиг влево  на 8 бит
 * ROL (для изменения входного значения для каждого раунда). Переменная D подвергается 
 * циклическому сдвигу влево на 1 бит, после чего для C выполняется XOR с результатом
 * сложения tA, tB и соответсвующего подключа. D подвергается XOR с tA и удвоенным tB,
 * и, наконец, С циклически сдвигается на 1 бит влево - фактически, являя собой псевдо-
 * преобразование Адамара (PHP). Далее на каждом этапе происходит диффузия переменных
 * путём перестановки. Завершающие этапы - "конечное отбеливание" добавлением подключей,
 * после чего вышеуказанные 32-битыне слова объединяются в один исходный вектор plain. 
 * 
 **************************************************************************************/

BYTE* TwoFish_encrypt(TwoFish *tf, BYTE *plain) {
    UINT A = (plain[0] << 24) + (plain[1] << 16) + (plain[2] << 8) + plain[3],
        B = (plain[4] << 24) + (plain[5] << 16) + (plain[6] << 8) + plain[7],
        C = (plain[8] << 24) + (plain[9] << 16) + (plain[10] << 8) + plain[11],
        D = (plain[12] << 24) + (plain[13] << 16) + (plain[14] << 8) + plain[15];

    //Отбеливание
    A ^= tf->keys[0];
    B ^= tf->keys[1];
    C ^= tf->keys[2];
    D ^= tf->keys[3];

    //16-раундовая сеть Фейстеля
    for (int i = 0; i < 16; i++) {
        unsigned long long tA = h(A, tf->SBox, tf->k);
        unsigned long long tB = h(ROL(B, 8), tf->SBox, tf->k);

        D = ROL(D, 1);
        C ^= ((tA + tB + tf->keys[2 * i + 8]) & 0xFFFFFFFF);
        D ^= ((tA + 2 * tB + tf->keys[2 * i + 9]) & 0xFFFFFFFF);
        C = ROR(C, 1);

        if (i != 15) {
            UINT tmp = C;
            C = A;
            A = tmp;
            tmp = D;
            D = B;
            B = tmp;
        }
    }

    //Отбеливание
    A ^= tf->keys[4];
    B ^= tf->keys[5];
    C ^= tf->keys[6];
    D ^= tf->keys[7];

    plain[0] = (A >> 24) & 0xFF;
    plain[1] = (A >> 16) & 0xFF;
    plain[2] = (A >> 8) & 0xFF;
    plain[3] = A & 0xFF;
    plain[4] = (B >> 24) & 0xFF;
    plain[5] = (B >> 16) & 0xFF;
    plain[6] = (B >> 8) & 0xFF;
    plain[7] = B & 0xFF;
    plain[8] = (C >> 24) & 0xFF;
    plain[9] = (C >> 16) & 0xFF;
    plain[10] = (C >> 8) & 0xFF;
    plain[11] = C & 0xFF;
    plain[12] = (D >> 24) & 0xFF;
    plain[13] = (D >> 16) & 0xFF;
    plain[14] = (D >> 8) & 0xFF;
    plain[15] = D & 0xFF;
    return plain;
}



/***************************************************************************************
 *                              Функция TwoFish_decrypt
 * 
 * Функция TwoFish_decrypt является обратной функцией для TwoFish_encrypt, потому коммен-
 * тарии будут даны в сокращённом формате. Изначальный вектор, получаемый на вход, делится
 * на 4 32-битных слова, которые, после обратного отбеливания и обратного псевдопреобразо-
 * вания Адамара (PHP) прогоняется по сети Фейстеля в 16 раундах. Затем проводится ещё одно
 * обратное отбеливание, и полученные четыре 32-битных слова обратно объединяются в вектор.
 * 
 **************************************************************************************/

BYTE* TwoFish_decrypt(TwoFish *tf, BYTE *cipher) {
    UINT A = (cipher[0] << 24) + (cipher[1] << 16) + (cipher[2] << 8) + cipher[3],
        B = (cipher[4] << 24) + (cipher[5] << 16) + (cipher[6] << 8) + cipher[7],
        C = (cipher[8] << 24) + (cipher[9] << 16) + (cipher[10] << 8) + cipher[11],
        D = (cipher[12] << 24) + (cipher[13] << 16) + (cipher[14] << 8) + cipher[15];

    A ^= tf->keys[4];
    B ^= tf->keys[5];
    C ^= tf->keys[6];
    D ^= tf->keys[7];

    for (int i = 15; i >= 0; i--) {
        unsigned long long tA = h(A, tf->SBox, tf->k);
        unsigned long long tB = h(ROL(B, 8), tf->SBox, tf->k);

        C = ROL(C, 1);
        C ^= ((tA + tB + tf->keys[2 * i + 8]) & 0xFFFFFFFF);
        D ^= ((tA + 2 * tB + tf->keys[2 * i + 9]) & 0xFFFFFFFF);
        D = ROR(D, 1);

        if (i > 0) {
            UINT tmp = C;
            C = A;
            A = tmp;
            tmp = D;
            D = B;
            B = tmp;
        }
    }

    A ^= tf->keys[0];
    B ^= tf->keys[1];
    C ^= tf->keys[2];
    D ^= tf->keys[3];

    cipher[0] = (A >> 24) & 0xFF;
    cipher[1] = (A >> 16) & 0xFF;
    cipher[2] = (A >> 8) & 0xFF;
    cipher[3] = A & 0xFF;
    cipher[4] = (B >> 24) & 0xFF;
    cipher[5] = (B >> 16) & 0xFF;
    cipher[6] = (B >> 8) & 0xFF;
    cipher[7] = B & 0xFF;
    cipher[8] = (C >> 24) & 0xFF;
    cipher[9] = (C >> 16) & 0xFF;
    cipher[10] = (C >> 8) & 0xFF;
    cipher[11] = C & 0xFF;
    cipher[12] = (D >> 24) & 0xFF;
    cipher[13] = (D >> 16) & 0xFF;
    cipher[14] = (D >> 8) & 0xFF;
    cipher[15] = D & 0xFF;
    return cipher;
}



/***************************************************************************************
 *                          Функция process_directory
 * 
 * Функция рекурсивно обрабатывает все файлы и вложенные директории, находящиеся в ука-
 * занной директории. Каждый файл передаётся в функцию process_file для шифрования или
 * расшифровки, а вложенные директории обрабатываются рекурсивно.
 * 
 **************************************************************************************/

void process_directory(const char *dirpath, BYTE *key, size_t key_len, int encrypt) {
    struct dirent *entry;
    DIR *dp = opendir(dirpath);

    if (dp == NULL) {
        perror("Ошибка открытия директории");
        return;
    }

    while ((entry = readdir(dp))) {
        // Пропускаем "." и ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char input_path[1024];
        snprintf(input_path, sizeof(input_path), "%s/%s", dirpath, entry->d_name);

        struct stat path_stat;
        if (stat(input_path, &path_stat) != 0) {
            perror("Ошибка доступа к файлу/папке");
            continue;
        }

        if (S_ISREG(path_stat.st_mode)) {
            printf("Обрабатываем файл: %s\n", input_path);
            process_file(input_path, key, key_len, encrypt);
        } else if (S_ISDIR(path_stat.st_mode)) {
            printf("Обрабатываем директорию: %s\n", input_path);
            process_directory(input_path, key, key_len, encrypt);
        }
    }

    closedir(dp);
}



/***************************************************************************************
 *                               Функция process_file
 * 
 * Функция обрабатывает (шифрует или расшифровывает) файл "на месте", используя алгоритм
 * Twofish. Функция создаёт временный файл для промежуточных данных, а затем заменяет
 * оригинальный файл на этот временный.
 * 
 **************************************************************************************/

void process_file(const char *input_path, BYTE *key, size_t key_len, int encrypt) {
    // Создаём временный файл
    char temp_path[] = "temp_twofishXXXXXX";
    int temp_fd = mkstemp(temp_path);
    if (temp_fd == -1) {
        perror("Ошибка создания временного файла");
        return;
    }

    FILE *input_file = fopen(input_path, "rb");
    FILE *temp_file = fdopen(temp_fd, "wb");
    if (!input_file || !temp_file) {
        perror("Ошибка открытия файлов");
        if (input_file) fclose(input_file);
        if (temp_file) fclose(temp_file);
        unlink(temp_path);
        return;
    }

    TwoFish tf;
    TwoFish_init(&tf, key, key_len);

    BYTE buffer[16];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, 16, input_file)) > 0) {
        if (encrypt) {
            if (bytes_read < 16) {
                add_padding(buffer, bytes_read, 16);
            }
            TwoFish_encrypt(&tf, buffer);
            fwrite(buffer, 1, 16, temp_file);
        } else {
            TwoFish_decrypt(&tf, buffer);
            if (feof(input_file)) {
                if (!is_valid_padding(buffer, 16)) {
                    printf("Ошибка: Некорректный padding.\n");
                    fclose(input_file);
                    fclose(temp_file);
                    unlink(temp_path);
                    TwoFish_cleanup(&tf);
                    return;
                }
                bytes_read = remove_padding(buffer, 16);
            }
            fwrite(buffer, 1, bytes_read, temp_file);
        }
    }

    fclose(input_file);
    fclose(temp_file);
    TwoFish_cleanup(&tf);

    // Заменяем оригинальный файл временным
    if (rename(temp_path, input_path) != 0) {
        perror("Ошибка замены файла");
        unlink(temp_path);
    } else {
        printf("Файл '%s' успешно обработан.\n", input_path);
    }
}


//__main__
int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Использование: %s <input_path> <key> <mode>\n", argv[0]);
        printf("<key>: 16-байтный ключ в hex-формате (например, 000102030405060708090A0B0C0D0E0F)\n");
        printf("<mode>: 1 - шифрование, 0 - расшифровка\n");
        return 1;
    }

    const char *input_path = argv[1];
    const char *key_str = argv[2];
    int mode = atoi(argv[3]);

    if (strlen(key_str) != 32) {
        printf("Ошибка: Ключ должен содержать 32 символа (16 байт в hex-формате).\n");
        return 1;
    }

    BYTE key[16];
    parse_key(key_str, key);

    struct stat path_stat;
    if (stat(input_path, &path_stat) != 0) {
        perror("Ошибка доступа к пути");
        return 1;
    }

    if (S_ISREG(path_stat.st_mode)) {
        process_file(input_path, key, 128, mode);
    } else if (S_ISDIR(path_stat.st_mode)) {
        process_directory(input_path, key, 128, mode);
    } else {
        printf("Ошибка: '%s' не является файлом или директорией.\n", input_path);
        return 1;
    }

    return 0;
}