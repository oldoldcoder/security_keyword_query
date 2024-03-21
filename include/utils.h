/**
@author:heqi
@time:2024/03/19
@desc:定义一些通用的数据结构
*/
#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>

/*------------------------------常量定义-----------------------------*/
#define ARRAYLIST 100
#define BITMAP 10000
#define RESULT int
#define TRUE 1
#define FALSE 0
/*------------------------------可变长数组-----------------------------*/
struct ArrayList
{
    char ** elements;
    unsigned int length;
    unsigned int capacity;
    void (*deinit)(struct ArrayList *);
    void (*push)(struct ArrayList *, char *);
    char * (*at)(struct ArrayList *, int);
    // 是否非空
    int (*isEmpty)(struct ArrayList *);
}ArrayList;

void deinit(struct ArrayList *self);
void push(struct ArrayList *self, char * el);
char * at(struct ArrayList * self, int el);
int isEmpty(struct ArrayList * sel);
struct ArrayList * arrayList_init(int len);


/*---------------------操作bitmap的方法--------------------------*/
void set_bit(int *bitmap, int pos);
void clear_bit(int *bitmap, int pos);
RESULT test_bit(int *bitmap, int pos);
int * create_bit_map(int len);

#endif//UTILS_H