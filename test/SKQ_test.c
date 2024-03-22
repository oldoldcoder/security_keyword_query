/**
@author:heqi
@time:2024/03/19
@desc:skq的测试罢了
*/
#include "skq.h"
#include "utils.h"

// 执行skq的测试
void test(int i){
    init_constant();
    // 创建数据源
    data_owner ** arr = (data_owner **) malloc(sizeof (data_owner *) * i);
    for(int j = 0 ; j < i ; ++j){
        arr[j] = (data_owner *) malloc(sizeof (data_owner));
        skq_init_data_owner(arr[j],1);
        skq_read_file_2do(arr[j],NULL);
        skq_create_backward_index(arr[j]);
        skq_setup(arr[j]);
    }
    char * w = "abc";
    // 进行查询
    for(int j = 0 ; j < i ; j++){
        int ** bitmap = (int **) malloc(sizeof (int *));
        skq_search_wi_from_server(w,arr[j]->i,arr[j]->fileCnt,bitmap);
        // 打印获得的值
        for(int z = 0 ; z < BITMAP ; ++z){
            if(test_bit(*bitmap,z) == TRUE){
                printf("第%d号文件存在关键字%s\n",z,w);
            }
        }
        fflush(stdout);
        // 重新给上传值
        skq_insert_data_2server(w,arr[j]->i,arr[j]->fileCnt,bitmap);
        unsigned int len = 0;
        char * cip3 = skq_Fk_AES_encrypt_o(w,arr[0]->fileCnt,1,0,&len);
        int * record = hashmap_get(global_hashmap,cip3, len);
        int * record2 = hashmap_get(global_hashmap,caonima, len);
        printf("%d",j);
    }
    /*unsigned int len = 0;
    char * cip3 = skq_Fk_AES_encrypt_o(w,arr[0]->fileCnt,1,0,&len);
    int * record = hashmap_get(global_hashmap,cip3, len);
    int * record2 = hashmap_get(global_hashmap,caonima, len);*/
    printf("------------------------------------------------------------------------\n");
    for(int j = 0 ; j < i ; j++){
        int ** bitmap = (int **) malloc(sizeof (int *));
        skq_search_wi_from_server(w,arr[j]->i,arr[j]->fileCnt,bitmap);
        // 打印获得的值
        for(int z = 0 ; z < BITMAP ; ++z){
            if(test_bit(*bitmap,z) == TRUE){
                printf("第%d号文件存在关键字%s\n",z,w);
            }
        }
        fflush(stdout);
        // 重新给上传值
        skq_insert_data_2server("abc",arr[j]->i,arr[j]->fileCnt,bitmap);
    }

    for(int j = 0 ; j < i ; j++){
        skq_free_data_owner(arr[j]);
    }
}

int main(){


    // 创建数据源，读取随机数据
    // 测试单数据源
    test(1);

    // 测试双数据源
    test(2);

}