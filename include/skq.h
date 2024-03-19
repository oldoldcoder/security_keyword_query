/**
@author:heqi
@time:2024/03/19
@desc:定义我们的security keyword query数据结构
*/
#ifndef SKQ_H
#define SKQ_H

#include "stdio.h"
#include <openssl/aes.h>
#include "string.h"
#include "hashmap.h"

/*--------------------------常量定义-------------------------*/
// 16位的AES的密钥
#define AES_KEYWORD "42cb1661ebf50db9a9cd3f64ba7650e411e8d8029edbb3437bdb934f9890377e3f5f07d3c197054dd66ded53c65811c544aeb8eaad101e7a31250576fb7d4f28"
#define RESULT int
#define SUCCESS -4564
#define ERROR 165495
#define TRUE 1
#define FALSE 0
#define INITIAL_SIZE 2028
// 服务器的大型hashmap
extern struct hashmap_s * global_hashmap;
/*-------------------------结构定义区--------------------------*/
typedef struct data_owner{
    // 正向索引
    struct hashmap_s * hashmap_forward;
    // 反向索引
    struct hashmap_s * hashmap_backward;
    // 数据拥有者拥有fileCnt
    struct hashmap_s * fileCnt;
}data_owner;
/*-------------------------方法定义区--------------------------*/
// 加密函数
RESULT skq_Fk_AES_encrypt(char * key,const unsigned char * plain, unsigned char * ciphertext);
// 将前向hashmap转换为反向的hashmap
RESULT skq_create_backward_index(data_owner * doo);
// do的filecnt + 1
inline void do_add_file_cnt(data_owner * doo,char *c);
// 上传到服务器
void skq_upload_data_2server(data_owner * doo);
// 进行查询
RESULT skq_search_wi_from_server(const unsigned char * key,int ** bitmap);
// 按位异或操作，按照长度短的进行异或操作
RESULT skq_xor(const unsigned char * key,int * bitmap);

#endif//SKQ_H