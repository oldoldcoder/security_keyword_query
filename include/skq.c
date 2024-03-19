/**
@author:heqi
@time:2024/03/19
@desc:skq的实现罢了
*/

#include "stdio.h"
#include <openssl/aes.h>
#include "string.h"
#include "hashmap.h"
#include "skq.h"
#include "utils.h"
struct hashmap_s * global_hashmap;
int is_init = FALSE;
static void init_constant(){
    if(is_init == FALSE){
        // 初始化全局查询的map
        hashmap_create(INITIAL_SIZE,global_hashmap);

        is_init = TRUE;
    }
}
// 定义加密的aes函数
static void encrypt_aes(const unsigned char *plaintext,char *key, unsigned char *ciphertext) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_encrypt(plaintext, ciphertext, &aes_key);
}

// 加密函数
RESULT skq_Fk_AES_encrypt( char * key,const unsigned char * plain, unsigned char * ciphertext){
    if(plain == NULL || ciphertext == NULL){
        fprintf(stderr,"%s传递参数为空\n",__func__ );
        return ERROR;
    }
    // 填充key值到128位
    int len = (int )strlen(key);
    if(len > 128){
        fprintf(stderr,"传递的密钥长度过大\n");
        return ERROR;
    }
    // TODO 危险，这里copy字符串恐出问题
    char * arr = (char * ) malloc(sizeof (char ) * 129);
    for(int i = 0 ; i < len ; ++i){
        arr[i] = key[i];
    }
    for(int i = len ; i < 128 ;  ++i){
        arr[i] = AES_KEYWORD[i];
    }
    arr[128] = '\0';
    fflush(stderr);
    encrypt_aes(plain,arr,ciphertext);
    return SUCCESS;
}
// 正常迭代情况下返回0，需要删除的识货返回-1
static int transfer_map(void* const context, struct hashmap_element_s* const e) {
    struct hashmap_s * map = (struct hashmap_s *)context;
    // e.data都是可变数组的值
    struct ArrayList * data = (struct ArrayList* )e->data;
    // 拿到我们的file_id
    int * file_id =(int *)e->key;
    // 遍历关键字
    int len = data->length;
    for(int i = 0 ; i  < len ; ++i){
        char * c = data->at(data,i);
        // 这里得到的是bitmap
        int * bitmap = (int *)hashmap_get(map,c, strlen(c));
        if(bitmap != NULL){
            set_bit(bitmap,*file_id);
        }else{
            int * new = create_bit_map(-1);
            if(new == NULL){
                fprintf(stderr,"申请bitmap的内存错误\n");
                // 停止迭代
                return 1;
            }
            hashmap_put(map,c, strlen(c),new);
            set_bit(new,*file_id);
        }
    }
    // 返回0继续迭代
    return 0;
}

// 将前向hashmap转换为反向的hashmap
RESULT skq_create_backward_index(data_owner * doo){
    struct hashmap_s * forward = doo->hashmap_forward;
    // 迭代
    if(doo->hashmap_backward == NULL){
        if( 0 == hashmap_create(INITIAL_SIZE,doo->hashmap_backward)){
            return ERROR;
        }
    }
    // 放入迭代器中进行迭代，上下文传递backward的hashmap
    if( 0 != hashmap_iterate_pairs(forward,transfer_map,doo->hashmap_backward)){
        fprintf(stderr,"迭代过程出现了错误");
        return ERROR;
    }
    return SUCCESS;
}
// do的filecnt + 1
inline void do_add_file_cnt(data_owner * doo,char *c){
    int * len = hashmap_get(doo->fileCnt,c, strlen(c));
    // 拿出来 ++ 不需要放回去
    *len++;
}
// 上传到服务器
void skq_upload_data_2server(data_owner * doo){
    // net操作
    // connect()
    printf("upload 成功");
}
// 进行查询
RESULT skq_search_wi_from_server(const unsigned char * key,int ** bitmap){
    *bitmap = hashmap_get(global_hashmap,key, strlen(key));
    if(*bitmap == NULL){
        fprintf(stderr,"查询出错,未找到bitmap");
        fflush(stderr);
        return ERROR;
    }
    return SUCCESS;
}
// 按位异或操作，按照长度短的进行异或操作
RESULT skq_xor(const unsigned char * key,int * bitmap){
    // 进行异或操作
    int len = (int)strlen(key);
    for(int i = 0 ; i < len ; ++i){
        bitmap[i] = bitmap[i] ^ key[i];
    }
    // TODO bitmap疑惑不完全
    return SUCCESS;
}