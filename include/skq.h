/**
@author:heqi
@time:2024/03/19
@desc:定义我们的security keyword query数据结构
*/
#ifndef SKQ_H
#define SKQ_H

#include "stdio.h"
#include <openssl/hmac.h>
#include "string.h"
#include "hashmap.h"
#include "utils.h"
/*--------------------------常量定义-------------------------*/
// 64字节的AES的密钥
#define AES_KEYWORD "ebf50db942cb16616ca13b104756cd3aebf50db942cb16616ca13b104756cd3d"
#define RESULT int
#define TRUE 1
#define FALSE 0
#define SUCCESS 4564
#define ERROR 165495
#define INITIAL_SIZE 2028
// 服务器的大型hashmap
extern struct hashmap_s * global_hashmap;
extern const EVP_MD* MD;
/*-------------------------结构定义区--------------------------*/
typedef struct data_owner{
    // 正向索引
    struct hashmap_s * hashmap_forward;
    // 反向索引
    struct hashmap_s * hashmap_backward;
    // 数据拥有者拥有fileCnt
    struct hashmap_s * fileCnt;
    // 序号
    int i;
    // 是否反向索引已经建立完毕
    int is_back;
}data_owner;
/*-------------------------方法定义区--------------------------*/
// 初始化函数
void init_constant();
// 加密函数
RESULT skq_Fk_AES_encrypt(char * key,const unsigned char * plain, unsigned char * ciphertext,unsigned int * len);
// 将前向hashmap转换为反向的hashmap
RESULT skq_create_backward_index(data_owner * doo);
// do的filecnt + 1
inline void do_add_file_cnt(struct hashmap_s * fileCnt,char *c);
// 上传到服务器
void skq_upload_data_2server(data_owner * doo);
// 进行查询
RESULT skq_search_wi_from_server(char * word,int j ,struct hashmap_s *fileCnt,int ** bitmap);
// 按位异或操作，按照长度短的进行异或操作
RESULT skq_xor(char * key,int * bitmap,unsigned int len);
// 初始化一个data_owner
RESULT skq_init_data_owner(data_owner * doo,int i);
// 清空data_owner的内容
/**
 * 每个fileid可能都需要清除
 * */
RESULT skq_free_data_owner(data_owner * doo);
// 读取内容然后到我们的data_owner里面去
/**
 * 目前是random的进行
 * */
RESULT skq_read_file_2do(data_owner * doo ,char * fileDirectory);
// 上传到服务器的setup算法;数据终究会上传到directMap中去
RESULT skq_setup(data_owner * doo);
/**
 * 查询结束之后重新插入新值到服务器中去
 * */
 RESULT skq_insert_data_2server(char * word,int j,struct hashmap_s * fileCnt,int ** bitmap);
#endif//SKQ_H