#ifndef __TWO_FISH_H_
#define __TWO_FISH_H_

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

typedef unsigned int UINT;
typedef unsigned char BYTE;

typedef struct {
    UINT keys[40];      // Массив из 40 подклчей
    short k;            // Количество слов в ключе
    UINT *SBox;         // Массив S-бокса.
} TwoFish;

// Объявление функций
void TwoFish_init(TwoFish *tf, BYTE *key, size_t length);
void TwoFish_cleanup(TwoFish *tf);
BYTE* TwoFish_encrypt(TwoFish *tf, BYTE *plain);
BYTE* TwoFish_decrypt(TwoFish *tf, BYTE *cipher);
void TwoFish_printSubkeys(TwoFish *tf);
void process_file(const char *input_path, BYTE *key, size_t key_len, int encrypt);
void process_directory(const char *dirpath, BYTE *key, size_t key_len, int encrypt);

#endif
