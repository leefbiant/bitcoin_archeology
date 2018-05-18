#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <vector>
#include <string>
#include <string.h>
#include <openssl/ecdsa.h>
#include <iostream>
#include <iomanip>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <syscall.h>

using namespace std;
const int NID_secp256k1 = 714;


#ifndef debug
#define debug(fmt, args...) \
  do { \
    struct timeval tv; \
    gettimeofday(&tv, NULL); \
    struct tm tm_now = *localtime(&tv.tv_sec); \
    fprintf(stderr, "[%04d-%02d-%02d %02d:%02d:%02d]|%d|%ld(%s:%d:%s): " fmt "\n", tm_now.tm_year + 1900, tm_now.tm_mon + 1, tm_now.tm_mday, tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec, getpid(),syscall(SYS_gettid),__FILE__, __LINE__, __func__, ##args); \
  } while (0) 
#endif
