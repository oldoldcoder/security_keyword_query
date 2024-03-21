/**
@author:heqi
@time:2024/03/19
@desc:skq的实现罢了
*/

#include "stdio.h"
#include <openssl/hmac.h>
#include "string.h"
#include "hashmap.h"
#include "skq.h"
#include "utils.h"

struct hashmap_s * global_hashmap;
const EVP_MD * MD;
int is_init = FALSE;
void init_constant(){
    if(is_init == FALSE){
        MD = EVP_sha512();
        global_hashmap = (struct hashmap_s *) malloc(sizeof (struct hashmap_s));
        // 初始化全局查询的map
        if( 0 != hashmap_create(INITIAL_SIZE,global_hashmap)){
            fprintf(stderr,"初始化global_hashmap失败\n");
            return;
        }
        is_init = TRUE;
    }
}

// 加密函数
RESULT skq_Fk_AES_encrypt( char * key,const unsigned char * plain, unsigned char * ciphertext,unsigned int * len){
    if(plain == NULL || ciphertext == NULL){
        fprintf(stderr,"%s传递参数为空\n",__func__ );
        return ERROR;
    }
    HMAC(MD, key, strlen(key), plain, strlen(plain), ciphertext, len);

    if(*len == 0){
        printf("未加密的原文:%s\n",plain);
        fflush(stdout);
    }
    return SUCCESS;
}
// 正常迭代情况下返回0，需要删除的识货返回-1
static int transfer_map(void* const context, struct hashmap_element_s* const e) {
    struct hashmap_s * map = (struct hashmap_s *)context;
    // e.data都是可变数组的值
    struct ArrayList * data = (struct ArrayList* )e->data;
    // 拿到我们的file_id
    int file_id =atoi((char *)e->key);
    // 遍历关键字
    int len = data->length;
    for(int i = 0 ; i  < len ; ++i){
        char * c = data->at(data,i);
        // 这里得到的是bitmap
        int * bitmap = (int *)hashmap_get(map,c, strlen(c));
        if(bitmap != NULL){
            set_bit(bitmap,file_id);
        }else{
            int * new = create_bit_map(-1);
            if(new == NULL){
                fprintf(stderr,"申请bitmap的内存错误\n");
                // 停止迭代
                return 1;
            }
            hashmap_put(map,c, strlen(c),new);
            set_bit(new,file_id);
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
        if( 0 != hashmap_create(INITIAL_SIZE,doo->hashmap_backward)){
            return ERROR;
        }
    }
    // 放入迭代器中进行迭代，上下文传递backward的hashmap
    if( 0 != hashmap_iterate_pairs(forward,transfer_map,doo->hashmap_backward)){
        fprintf(stderr,"迭代过程出现了错误");
        return ERROR;
    }
    doo->is_back = TRUE;
    return SUCCESS;
}
// do的filecnt + 1
void do_add_file_cnt(struct hashmap_s * fileCnt,char *c){
    int * len = hashmap_get(fileCnt,c, strlen(c));
    if(len == NULL){
        len = (int *) malloc(sizeof (int));
        * len = 0;
        hashmap_put(fileCnt,c, strlen(c),&len);
    }
    // 拿出来 ++ 不需要放回去
    (*len)++;
}
// 上传到服务器
void skq_upload_data_2server(data_owner * doo){
    // net操作
    // connect()
    printf("upload 成功");
}
// 对于传入字符串加密
char * skq_Fk_AES_encrypt_o(char * word,struct hashmap_s *fileCnt,int j,int zn,unsigned int *retLen){
    int wordL = strlen(word);
    int * a = hashmap_get(fileCnt,word,wordL);
    // 如果读出来为空的时候，我们设置为一个0值重新放进去
    if(a == NULL){
        a = (int *) malloc(sizeof (int ));
        * a = 0;
        hashmap_put(fileCnt,word, strlen(word),a);
    }
    char c1[12];
    char c2[12];
    sprintf(c1,"%d", *a);
    sprintf(c2,"%d",j);
    int aL = strlen(c1);
    int jL = strlen(c2);
    int lastL = wordL + aL + jL;
    char * plain = (char * ) malloc(sizeof (char ) * (lastL + 2));

    for(int i = 0; i < lastL ; ++i){
        if(i < wordL){
            plain[i] = word[i];
        }else if(i < (wordL + aL)){
            plain[i] = c1[i - wordL];
        }else{
            plain[i] = c2[i - wordL - aL];
        }
    }
//    for(int i = 0; i < lastL ; ++i){
//        if(i < aL){
//            plain[i] = c1[i];
//        } else if(i < aL + jL){
//            plain[i] = c2[i - aL - jL];
//        }else{
//            plain[i] = word[i];
//        }
//        if(i < wordL){
//        }else if(i < (wordL + aL)){
//            plain[i] = c1[i - wordL];
//        }else{
//            plain[i] = c2[i - wordL - aL];
//        }
//    }

    plain[lastL] = zn + '0';
    plain[lastL + 1] = '\0';
    char * cipherText = (char * ) malloc(sizeof (char ) * EVP_MAX_MD_SIZE);
    // 进行加密
    skq_Fk_AES_encrypt(AES_KEYWORD,(const unsigned char *)plain,(unsigned char *)cipherText,retLen);
    return cipherText;
}

// 进行查询
RESULT skq_search_wi_from_server(char * word,int j ,struct hashmap_s * fileCnt,int ** bitmap){


    unsigned int len = 0;
    // 首先获得了第一个
    char * cip1 = skq_Fk_AES_encrypt_o(word,fileCnt,j,0,&len);

    // 将cip1按照len值把二进制给她转换成字符串
    unsigned int cip1L = len;
    // TODO word转换为key的流程
    *bitmap = hashmap_get(global_hashmap,cip1, cip1L);
    if(*bitmap == NULL){
        fprintf(stderr,"查询出错,未找到bitmap");
        fflush(stderr);
        return ERROR;
    }
    char * cip2 = skq_Fk_AES_encrypt_o(word,fileCnt,j,1,&len);

    // 进行异或操作
    skq_xor(cip2,*bitmap,len);
    // 将fileCnt ++,同时重新上传
    do_add_file_cnt(fileCnt,word);
    // 删除这个pair对
    hashmap_remove(global_hashmap,cip1, cip1L);
    free(cip1);
    free(cip2);

    return SUCCESS;
}

RESULT skq_insert_data_2server(char * word,int j,struct hashmap_s *fileCnt,int ** bitmap){
    if(*bitmap == NULL){
        return ERROR;
    }
    unsigned int len = 0;
    // TODO 加密遇到了问题，cip1的长度不可求
    // 加密我们的关键字
    char * cip1 = skq_Fk_AES_encrypt_o(word,fileCnt,j,0,&len);

    unsigned int cip1L = len;
    // 加密我们的Cij
    char * cip2 = skq_Fk_AES_encrypt_o(word,fileCnt,j,1,&len);
    // 进行异或
    skq_xor(cip2,*bitmap,len);
    // 上传到服务器
    if(0 != hashmap_put(global_hashmap,cip1, cip1L,*bitmap)){
        fprintf(stderr,"未上传数据至服务器\n");
        return ERROR;
    }
    free(cip1);
    free(cip2);
    return SUCCESS;
}
// 按位异或操作，按照长度短的进行异或操作
RESULT skq_xor(char * key,int * bitmap,unsigned int len){
    if(bitmap == NULL){
        fprintf(stderr,"bitmap是空值\n");
        fflush(stderr);
        return ERROR;
    }
    for(unsigned int i = 0 ; i < len ; ++i){
        bitmap[i] = bitmap[i] ^ key[i];
    }
    return SUCCESS;
}
// 初始化一个data_owner
RESULT skq_init_data_owner(data_owner * doo,int i){
    doo->hashmap_forward = (struct hashmap_s *) malloc(sizeof (struct hashmap_s));
    doo->hashmap_backward = (struct hashmap_s *) malloc(sizeof (struct hashmap_s));
    doo->fileCnt = (struct hashmap_s *) malloc(sizeof (struct hashmap_s));

    if(0 != hashmap_create(INITIAL_SIZE,doo->hashmap_forward)){
        fprintf(stderr,"初始化hashmap_backward失败\n");
        return ERROR;
    }
    if( 0 != hashmap_create(INITIAL_SIZE,doo->hashmap_backward)){
        fprintf(stderr,"初始化hashmap_backward失败\n");
        return ERROR;
    }
    if( 0 != hashmap_create(INITIAL_SIZE,doo->fileCnt)){
        fprintf(stderr,"初始化hashmap_backward失败\n");
        return ERROR;
    }
    doo->i = i;
    doo->is_back = FALSE;
    return SUCCESS;
}
// 定义便利的时候清除内容的函数
static int free_hashmap(void* const context, struct hashmap_element_s* const e) {
    // 清除正向索引map
    if(*((int *)context) == 1){
        struct ArrayList * al = (struct ArrayList *)e->data;
        // 清除内容
        al->deinit(al);
        return -1;
    }// 清除反向索引map  清除filecnt的内容
    else if(*((int *)context) == 2 || *((int *)context) == 3){
        int * a = (int *) e->data;
        free(a);
        return -1;
    }
    return -1;
}
// 清空data_owner的内容
RESULT skq_free_data_owner(data_owner * doo){
    /**
     * doo的forward里面每个key对应的value类型是char * 类型的字符串，需要一个个释放
     * backward里面每个key对应一个bit_map
     * filecnt里面每个key对应一个int*，也需要释放
     * */
    int type = 1;
    int is_false = 0;
    if( 0 != hashmap_iterate_pairs(doo->hashmap_forward,free_hashmap,&type)){
        // 错误处理
        is_false = TRUE;
        fprintf(stderr,"释放hashmap_forward失败\n");
    }
    hashmap_destroy(doo->hashmap_forward);
    type = 2;
    if( 0 != hashmap_iterate_pairs(doo->hashmap_backward,free_hashmap,&type)){
        // 错误处理
        is_false = TRUE;
        fprintf(stderr,"释放hashmap_backward失败\n");
    }
    hashmap_destroy(doo->hashmap_backward);
    type = 3;
    if( 0 != hashmap_iterate_pairs(doo->fileCnt,free_hashmap,&type)){
        // 错误处理
        is_false = TRUE;
        fprintf(stderr,"释放fileCnt失败\n");
    }
    hashmap_destroy(doo->fileCnt);
    if(is_false == TRUE){
        return ERROR;
    }
    fflush(stderr);
    return SUCCESS;
}
// 读取内容然后到我们的data_owner里面去
RESULT skq_read_file_2do(data_owner * doo,char * fileDirectory){
    if(doo->hashmap_forward == NULL || doo->hashmap_backward == NULL || doo->fileCnt == NULL){
        fprintf(stderr,"doo未完成初始化,错误\n");
        fflush(stderr);
        return ERROR;
    }
    /**
     * 虚拟读取文件夹的内容
     * */
     // 虚拟一万个文件，每个文件里面给填充随机的字符串
    for(int i = 0 ; i < 100 ; i ++){

        char * str = (char *) malloc(sizeof (char ) * 11);
        struct ArrayList * arr = arrayList_init(110);
        for(int z = 0 ; z <= 100; z ++){
            int upper = (random() % 10) + 1;
            char * no = (char *) malloc(sizeof (char ) * upper);
            for(int m = 0 ; m < upper ; m ++){
                no[m] = 'a' + (random() % 3);
            }
            arr->push(arr,no);
        }
        // 文件号转换为char类型
        sprintf(str, "%d", i);
        // 填充到前向表格中去
        hashmap_put(doo->hashmap_forward,str, strlen(str),arr);
    }
    return SUCCESS;

}
// context传递为doo的filecnt，我们需要使用的
static int encrypt_data(void* const context, struct hashmap_element_s* const e){
    int * bitmap = (int *)e->data;
    char * wi = (char *)e->key;
    data_owner  * doo = (data_owner *)context;
    skq_insert_data_2server(wi,doo->i,doo->fileCnt,&bitmap);
    return 0;
}
// 上传到服务器的setup算法;数据终究会上传到directMap中去
RESULT skq_setup(data_owner * doo){
    int i = doo->i;
    // 建立反向索引
    if(doo->is_back == FALSE){
        skq_create_backward_index(doo);
    }
    // 数据加密，对于每一个wi
    if(0 != hashmap_iterate_pairs(doo->hashmap_backward,encrypt_data,doo)){
        // 打印错误
        fprintf(stderr,"backward的数据上传到服务器的过程遇到错误\n");
        fflush(stderr);
        return ERROR;
    }
    return SUCCESS;
}