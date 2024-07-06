/**
@author:heqi
@time:2024/03/19
@desc:skq的实现罢了
*/

#include "stdio.h"
#include <openssl/hmac.h>
#include "string.h"

#include "skq.h"
#include "utils.h"
#include<unordered_map>

using namespace std;

char* caonima = NULL;

unordered_map<char*, void*>* global_hashmap;

const EVP_MD* MD;
int is_init = FALSE;
void init_constant() {
	if (is_init == FALSE) {
		global_hashmap = new unordered_map<char*, void*>;
		MD = EVP_sha512();
		is_init = TRUE;
	}
}

// 加密函数
RESULT skq_Fk_AES_encrypt(char* key, const unsigned char* plain, unsigned char* ciphertext, unsigned int* len) {
	if (plain == NULL || ciphertext == NULL) {
		fprintf(stderr, "%s put in param is null\n", __func__);
		return ERROR;
	}
	HMAC(MD, key, strlen(key), plain, strlen(reinterpret_cast<const char*>(plain)), ciphertext, len);

	if (*len == 0) {
		printf("Unencrypted original text:%s\n", plain);
		fflush(stdout);
	}

	return SUCCESS;
}

// 将前向hashmap转换为反向的hashmap，每次对于一个doo进行作用
RESULT skq_create_backward_index(data_owner* doo) {
	unordered_map<char*, void*>* forward = doo->hashmap_forward;
	unordered_map<char*, void*>* backward = doo->hashmap_backward;
	// 迭代
	if (doo->hashmap_backward == NULL) {
		doo->hashmap_backward = new unordered_map<char*, void*>;
	}
	// 放入迭代器中进行迭代，上下文传递backward的hashmap
	for (auto it = forward->begin(); it != forward->end(); ++it) {

		vector<char*>* data = (vector<char*> *)it->second;
		// 拿到我们的file_id
		int file_id = atoi((char*)it->first);
		// 遍历关键字
		int len = data->size();
		for (int i = 0; i < len; ++i) {
			char* c = data->at(i);

			// 这里得到的是bitmap
			auto  it = backward->find(c);
			if (it == backward->end()) {
				int* newBitMap = create_bit_map(-1);
				if (newBitMap == NULL) {
					fprintf(stderr, "Memory error in applying for Bitmap\n");
					// 停止迭代
					return ERROR;
				}
				backward->insert(std::make_pair(c, reinterpret_cast<void*>(newBitMap)));
				set_bit(newBitMap, file_id);
			}
			else {
				int* bitmap = (int*)it->second;
				set_bit(bitmap, file_id);
			}
		}
	}
	doo->is_back = TRUE;
	return SUCCESS;
}
// do的filecnt + 1
void do_add_file_cnt(unordered_map<char*, int* >* fileCnt, char* c) {

	int* len = (*fileCnt)[c];
	if (len == nullptr) {
		len = (int*)malloc(sizeof(int));
		*len = 0;
		(*fileCnt)[c] = len;
	}
	// 拿出来 ++ 不需要放回去
	(*len)++;
}
// 上传到服务器
void skq_upload_data_2server(data_owner* doo) {
	// net操作
	// connect()
	printf("upload success\n");
}
// 对于传入字符串加密
char* skq_Fk_AES_encrypt_o(char* word, unordered_map<char*, int* >* fileCnt, int j, int zn, unsigned int* retLen) {
	int wordL = strlen(word);
	auto it = fileCnt->find(word);
	int* a = NULL;
	if (it == fileCnt->end()) {
		int* a = (int*)malloc(sizeof(int));
		*a = 0;
		fileCnt->insert(make_pair(word, a));
	}
	else {
		a = it->second; //确保
	}

	char c1[12];
	char c2[12];
	sprintf(c1, "%d", *a);
	sprintf(c2, "%d", j);
	int aL = strlen(c1);
	int jL = strlen(c2);
	int lastL = wordL + aL + jL;
	char* plain = (char*)malloc(sizeof(char) * (lastL + 2));

	for (int i = 0; i < lastL; ++i) {
		if (i < wordL) {
			plain[i] = word[i];
		}
		else if (i < (wordL + aL)) {
			plain[i] = c1[i - wordL];
		}
		else {
			plain[i] = c2[i - wordL - aL];
		}
	}

	plain[lastL] = zn + '0';
	plain[lastL + 1] = '\0';
	char* cipherText = (char*)malloc(sizeof(char) * EVP_MAX_MD_SIZE);
	// 进行加密
	skq_Fk_AES_encrypt(AES_KEYWORD, (const unsigned char*)plain, (unsigned char*)cipherText, retLen);
	return cipherText;
}

// 进行查询
RESULT skq_search_wi_from_server(char* word, int j, unordered_map<char*, int* >* fileCnt, int** bitmap) {

	unsigned int len = 0;
	// 首先获得了第一个
	char* cip1 = skq_Fk_AES_encrypt_o(word, fileCnt, j, 0, &len);
	// 将cip1按照len值把二进制给她转换成字符串
	unsigned int cip1L = len;
	// TODO word转换为key的流程
	auto it = global_hashmap->find(cip1);
	if (it == global_hashmap->end()) {
		fprintf(stderr, "Query error, Bitmap not found");
		fflush(stderr);
		return ERROR;
	}
	else {
		*bitmap = (int*)it->second;
		char* cip2 = skq_Fk_AES_encrypt_o(word, fileCnt, j, 1, &len);
		// 进行异或操作
		skq_xor(cip2, *bitmap, len);
		// 将fileCnt ++,同时重新上传
		do_add_file_cnt(fileCnt, word);
		free(cip2);
		global_hashmap->erase(cip1);

		// 释放掉之前的cip1
		free(it->first);
		free(cip1);
		return SUCCESS;
	}
}

RESULT skq_insert_data_2server(char* word, int j, unordered_map<char*, int*>* fileCnt, int** bitmap) {
	if (*bitmap == NULL) {
		return ERROR;
	}
	unsigned int len = 0;
	// 加密我们的关键字
	char* cip1 = skq_Fk_AES_encrypt_o(word, fileCnt, j, 0, &len);
	unsigned int cip1L = len;
	// 加密我们的Cij
	char* cip2 = skq_Fk_AES_encrypt_o(word, fileCnt, j, 1, &len);
	// 进行异或
	skq_xor(cip2, *bitmap, len);
	global_hashmap->insert(make_pair(cip1, reinterpret_cast<void*>(*bitmap)));

	char* cip3 = skq_Fk_AES_encrypt_o(word, fileCnt, j, 0, &len);
	// 这两句应该是debug时候写的
	int* record = (int*)global_hashmap->find(cip3)->second;

	skq_xor(cip2, record, len);
	if (strcmp("abc", word) == 0) {
		for (int z = 0; z < BITMAP; ++z) {
			if (test_bit(record, z) == TRUE) {
				printf("bitmap ok!\n");
			}
		}
	}
	// cip1上传了，所以不能删除
	free(cip2);
	return SUCCESS;
}
// 按位异或操作，按照长度短的进行异或操作
RESULT skq_xor(char* key, int* bitmap, unsigned int len) {
	if (bitmap == NULL) {
		fprintf(stderr, "Bitmap is a null value\n");
		fflush(stderr);
		return ERROR;
	}
	for (unsigned int i = 0; i < len; ++i) {
		bitmap[i] = bitmap[i] ^ key[i];
	}
	return SUCCESS;
}
// 初始化一个data_owner
RESULT skq_init_data_owner(data_owner* doo, int i) {
	doo->hashmap_forward = new  unordered_map<char*, void*>();
	doo->hashmap_backward = new  unordered_map<char*, void*>();;
	doo->fileCnt = new  unordered_map<char*, int*>();;

	// 检查 unordered_map 是否成功分配内存
	if (!doo->hashmap_forward || !doo->hashmap_backward || !doo->fileCnt) {
		fprintf(stderr, "Failed to initialize unordered_map\n");
		return -1; // 或定义的 ERROR 常量
	}
	doo->i = i;
	doo->is_back = FALSE;
	return SUCCESS;
}

// 清空data_owner的内容
RESULT skq_free_data_owner(data_owner* doo) {
	/**
	 * doo的forward里面每个key对应的value类型是char * 类型的字符串，需要一个个释放
	 * backward里面每个key对应一个bit_map
	 * filecnt里面每个key对应一个int*，也需要释放
	 * */
	int is_false = 0;
	// key char * 类型 value vector类型 vector里面的值是backward 和 forward共用的
	for (auto it = doo->hashmap_forward->begin(); it != doo->hashmap_forward->end(); it++) {
		char* word = it->first;
		vector<char*>* arr = (vector<char*> *) it->second;
		// malloc 申请的这样释放
		free(word);
		// 释放vector以及内部的值
		for (auto it = arr->begin(); it != arr->end(); ++it) {
			char* ptr = *it;
			free(ptr);
		}
		arr->clear();
		delete arr;
	}
	// 释放backward
	for (auto it = doo->hashmap_backward->begin(); it != doo->hashmap_backward->end(); it++) {
		// 内部的key 已经给释放了
		int* bitmap = (int*)it->second;
		free(bitmap);

	}
	// 释放fileCnt
	for (auto it = doo->fileCnt->begin(); it != doo->fileCnt->end(); it++) {
		int* len = (int*)it->second;
		free(len);
	}

	delete(doo->hashmap_forward);
	delete(doo->hashmap_backward);
	delete(doo->fileCnt);
	if (is_false == TRUE) {
		return ERROR;
	}
	return SUCCESS;
}

// 重新设置未初始化，释放global_hashmap,初始化定义为空
static void skq_free_global_map() {
	for (auto it = global_hashmap->begin(); it != global_hashmap->end(); it++) {
		is_init = FALSE;
		char* cip1 = (char*)it->first;
		free(cip1);
		// second是bitmap，上面去释放
	}
}

// 读取内容然后到我们的data_owner里面去
RESULT skq_read_file_2do(data_owner* doo, char* fileDirectory) {
	if (doo->hashmap_forward == NULL || doo->hashmap_backward == NULL || doo->fileCnt == NULL) {
		fprintf(stderr, "Doo initialization not completed, error\n");
		fflush(stderr);
		return ERROR;
	}
	/**
	 * 虚拟读取文件夹的内容
	 * */
	 // 虚拟一万个文件，每个文件里面给填充随机的字符串
	for (int i = 0; i < 100; i++) {
		char* str = (char*)malloc(sizeof(char) * 11);
		vector<char*>* arr = new vector<char*>(110);
		// 模拟一百次读取文件的操作
		for (int z = 0; z <= 10; z++) {
			// upper是模拟的长度
			int upper = (rand() % 10) + 1;
			char* no = (char*)malloc(sizeof(char) * upper + 1);
			if (no == NULL) {
				printf("Error in applying for no memory\n");
				return ERROR;
			}
			for (int m = 0; m < upper; m++) {
				// 只会随机取abc这三个字母填充
				no[m] = 'a' + (rand() % 3);
			}
			no[upper] = '\0';
			// 如果存在abc就打印出来看看了
			if (strcmp("abc", no) == 0) {
				printf("init stage :%d include abc\n", i);
			}
			arr->push_back(no);
		}
		// 文件号转换为char类型
		sprintf(str, "%d", i);
		doo->hashmap_forward->insert(std::make_pair(str, reinterpret_cast<void*>(arr)));
	}
	return SUCCESS;

}
// 上传到服务器的setup算法;数据终究会上传到directMap中去
RESULT skq_setup(data_owner* doo) {
	int i = doo->i;
	// 建立反向索引
	if (doo->is_back == FALSE) {
		skq_create_backward_index(doo);
	}

	for (auto it = doo->hashmap_backward->begin(); it != doo->hashmap_backward->end(); ++it) {
		int* bitmap = (int*)it->second;
		char* wi = (char*)it->first;

		if (strcmp("abc", wi) == 0) {
			for (int z = 0; z < BITMAP; ++z) {
				if (test_bit(bitmap, z) == TRUE) {
					printf("%d th file include %s\n", z, wi);
				}
			}
		}

		skq_insert_data_2server(wi, doo->i, doo->fileCnt, &bitmap);
		return SUCCESS;
	}
}