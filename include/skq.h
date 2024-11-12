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
#include<string>
#include<unordered_map>
#include "utils.h"
/*--------------------------常量定义-------------------------*/
// 64字节的AES的密钥
#define AES_KEYWORD "ebf50db942cb16616ca13b104756cd3aebf50db942cb16616ca13b104756cd3d"
#define RESULT int
#define TRUE 1
#define FALSE 0
#define SUCCESS 1
#define ERROR 0
#define INITIAL_SIZE 2028
#ifdef _WIN32
#define EXPORT_SYMBOL __declspec(dllexport)
#else
#define EXPORT_SYMBOL __attribute__((visibility("default")))
#endif

using namespace std;
struct char_ptr_hash {
	size_t operator()(const char* s) const {
		return hash<string>()(string(s));
	}
};
// 自定义比较函数
struct char_ptr_equal {
	bool operator()(const char* s1, const char* s2) const {
		return strcmp(s1, s2) == 0;
	}
};
struct CustomHash {
	size_t operator()(const char* s) const {
		size_t hash = 0;
		for (size_t i = 0; i < EVP_MAX_MD_SIZE; ++i) {
			hash = hash * 31 + s[i];
		}
		return hash;
	}
};
struct cipherText_ptr_equal {
	bool operator()(const char* s1, const char* s2) const {
		for (int i = 0; i < EVP_MAX_MD_SIZE; ++i) {
			if (s1[i] != s2[i])
				return false;
		}
		return true;
	}
};

extern unordered_map<char*, void*, CustomHash, cipherText_ptr_equal>* global_hashmap;
extern const EVP_MD* MD;
extern char* caonima;
/*-------------------------结构定义区--------------------------*/

typedef struct data_owner {

	// 正向索引
	unordered_map<char*, void*, char_ptr_hash, char_ptr_equal>* hashmap_forward;
	// 反向索引
	unordered_map<char*, void*, char_ptr_hash, char_ptr_equal>* hashmap_backward;
	// 数据拥有者拥有fileCnt
	unordered_map<char*, int*, char_ptr_hash, char_ptr_equal>* fileCnt;
	// 序号
	int i;
	// 是否反向索引已经建立完毕
	int is_back;
}data_owner;
// 处理CPP导出DLL的内容
#ifdef __cplusplus
extern "C" {
#endif

	EXPORT_SYMBOL int init_algo(char* dataFilePath, data_owner* data);
	EXPORT_SYMBOL int query_algo(data_owner* data, char* queryFilePath, char* resultFilePath);
	EXPORT_SYMBOL int free_algo(data_owner* data);
	EXPORT_SYMBOL void init_constant();

#ifdef __cplusplus
}
#endif

/*-------------------------方法定义区--------------------------*/

// 初始化函数
EXPORT_SYMBOL void init_constant();
// 加密函数
RESULT skq_Fk_AES_encrypt(char* key, const unsigned char* plain, unsigned char* ciphertext, unsigned int* len);
// 将前向hashmap转换为反向的hashmap
RESULT skq_create_backward_index(data_owner* doo);
// do的filecnt + 1
inline void do_add_file_cnt(unordered_map<char*, int*, char_ptr_hash, char_ptr_equal>* fileCnt, char* c);
// 上传到服务器
void skq_upload_data_2server(data_owner* doo);
// 进行查询
RESULT skq_search_wi_from_server(char* word, int j, unordered_map<char*, int*, char_ptr_hash, char_ptr_equal>* fileCnt, int** bitmap);
// 按位异或操作，按照长度短的进行异或操作
RESULT skq_xor(char* key, int* bitmap, unsigned int len);
// 初始化一个data_owner
RESULT skq_init_data_owner(data_owner* doo, int i);
// 清空data_owner的内容
/**
 * 每个fileid可能都需要清除
 * */
RESULT skq_free_data_owner(data_owner* doo);
// 读取内容然后到我们的data_owner里面去
/**
 * 目前是random的进行
 * */
RESULT skq_read_file_2do(data_owner* doo, char* fileDirectory);
// 上传到服务器的setup算法;数据终究会上传到directMap中去
RESULT skq_setup(data_owner* doo);
/**
 * 查询结束之后重新插入新值到服务器中去
 * */
RESULT skq_insert_data_2server(char* word, int j, unordered_map<char*, int*, char_ptr_hash, char_ptr_equal>* fileCnt, int** bitmap);

RESULT skq_write_res2file(int** bitmap, char* w, char* resFile);
char* skq_Fk_AES_encrypt_o(char* word, unordered_map<char*, int*, char_ptr_hash, char_ptr_equal >* fileCnt, int j, int zn, unsigned int* retLen);

char* skq_get_query_param(char* queryFile);

void skq_free_global_map();
#endif//SKQ_H