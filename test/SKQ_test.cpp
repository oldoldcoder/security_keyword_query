/**
@author:heqi
@time:2024/03/19
@desc:skq的测试罢了
*/
#include "skq.h"
#include "utils.h"
void printfTime(char* desc,clock_t start) {
    double cpu_time_used = ((double)(clock() - start)) / CLOCKS_PER_SEC;

    printf("%s used: %f seconds\n",desc, cpu_time_used);
}


int main() {
    clock_t start, end;
    start = clock();
    data_owner dataOwner;
    init_constant();
    int initResult = init_algo("/root/heqi/encryption_algorithm/security_keyword_query/data/data.txt",&dataOwner);
    if (initResult !=  SUCCESS) {
        printf("Failed to initialize algorithm");
    }
    printfTime("init",start);
    start = clock();

    int queryResult = query_algo(&dataOwner,"/root/heqi/encryption_algorithm/security_keyword_query/data/query.txt","D:\\study\\code\\ClionProject\\security_keyword_query\\data\\res.txt");
    if (queryResult != SUCCESS) {
        printf("Failed to query_algo algorithm");
    }

    printfTime("query",start);
}