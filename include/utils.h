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

/*---------------------操作bitmap的方法--------------------------*/
void set_bit(int* bitmap, int pos);
void clear_bit(int* bitmap, int pos);
RESULT test_bit(int* bitmap, int pos);
int* create_bit_map(int len);

#endif//UTILS_H