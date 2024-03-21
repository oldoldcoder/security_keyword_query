
#include "utils.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

void deinit(struct ArrayList *self)
{
    free(self->elements);
}

void push(struct ArrayList *self, char * el)
{
    if (self->length < self->capacity)
    {
        self->elements[self->length] = el;
        self->length++;
        return;
    }
    char ** original = self->elements;
    self->elements = (char **)malloc( self->capacity * 2 * sizeof(char *));
    if(self->elements == NULL){
        fprintf(stderr,"realloc 重新分配内存失败!");
        // 重新指向原有的original
        self->elements = original;
        fflush(stderr);
        return;
    }else{
        // malloc success
        memcpy(self->elements,original,self->capacity * 2 * sizeof (char *));
        self->capacity  = self->capacity * 2;
    }

    self->elements[self->length] = el;
    self->length++;
}


char * at(struct ArrayList * self, int el)
{
    return self->elements[el];
}
int isEmpty(struct ArrayList * sel){
    return sel->length == 0 ? TRUE : FALSE;
}
struct ArrayList * arrayList_init(int len)
{
    struct ArrayList * al = (struct ArrayList *) malloc(sizeof(struct ArrayList));
    al->elements =  malloc(len == -1 ? ARRAYLIST : len * sizeof(char *));
    al->length = 0;
    al->capacity = len == -1 ? ARRAYLIST : len;
    al->at = & at;
    al->push = & push;
    al->deinit = &deinit;
    al->isEmpty = & isEmpty;
    return al;
}

// 设置位
void set_bit(int *bitmap, int pos) {
    int index = pos / ((int )(sizeof (int) * 8));  // 计算在数组中的索引
    int offset = pos % ((int )(sizeof (int) * 8)); // 计算在整数中的偏移量
    bitmap[index] |= (1 << offset); // 将对应位设置为1
}

// 清除位
void clear_bit(int *bitmap, int pos) {
    int index = pos / ((int )(sizeof (int) * 8));
    int offset = pos % ((int )(sizeof (int) * 8));
    bitmap[index] &= ~(1 << offset); // 将对应位设置为0
}

// 测试位
RESULT test_bit(int *bitmap, int pos) {
    int index = pos / ((int )(sizeof (int) * 8));
    int offset = pos % ((int )(sizeof (int) * 8));
    return (bitmap[index] & (1 << offset)) != 0 ? TRUE : FALSE; // 测试对应位是否为1
}
int * create_bit_map(int len){
    int cap = 0;
    if(len == -1){
        cap = BITMAP / ((int )(sizeof (int) * 8));
    }else{
        cap = len / ((int )(sizeof (int) * 8));
    }
    int * bit_map = malloc((cap + 1) * sizeof (int ));
    memset(bit_map,0,(cap + 1) * sizeof (int ));

    return bit_map;
}