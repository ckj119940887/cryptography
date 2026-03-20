/*
 * @        file: sha512.h
 * @ description: header file for sha3.c
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#ifndef __ROCKY_SHA3__H
#define __ROCKY_SHA3__H

#define ERR_OK           0
#define ERR_ERR         -1  /* generic error */
#define ERR_INV_PARAM   -2  /* invalid parameter */
#define ERR_TOO_LONG    -3  /* too long */
#define ERR_STATE_ERR   -4  /* state error */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef struct {
    uint64_t high; /* high 64 bits */
    uint64_t low;  /*  low 64 bits */
} uint128_t;

/*
 * Standard:
 *   SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
 *   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 *
 * Understanding-Cryptography-Keccak.pdf
 * SHA-3 and The Hash Function Keccak
 * https://www.crypto-textbook.com/download/Understanding-Cryptography-Keccak.pdf
 */

typedef enum sha3_algorithm {
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHAKE128,
    SHAKE256
}SHA3_ALG;

typedef struct sha3_context {
    /* intermedia hash value for each block */
    // Keccak 的核心状态
    // 一共 25 个 lane，每个 lane 64 bit，总共 1600 bit
    // 注意这里数组下标使用的是 lane[y][x] 的布局
    uint64_t lane[5][5];      /* 5 x 5 x 64 = 1600 bits */

    /* last block */
    struct {
    	// last.buf 里当前已经用了多少字节
        uint32_t used;      /* used bytes */
        // 末尾残留块缓冲区
        // 200 字节 = 1600 bit，对应整个状态宽度
        // 实际每次吸收只会用到前 r 字节
        uint8_t  buf[200];  /* block data buffer, 200 x 8 = 1600 bits */
    }last;

    SHA3_ALG alg;

    // 这段表格是 Keccak 的参数关系
    // 对 SHA-3 / SHAKE 使用的就是 l=6, w=64, b=1600
    /*
     * |-------------------------------------------------------------|
     * | l          | 0    | 1    | 2    | 3    | 4    | 5    | 6    |
     * |-------------------------------------------------------------|
     * | w = 2^l    | 1    | 2    | 4    | 8    | 16   | 32   | 64   |
     * |-------------------------------------------------------------|
     * | b = 25*2^l | 25   | 50   | 100  | 200  | 400  | 800  | 1600 |
     * |-------------------------------------------------------------|
     * | SHA3: l = 6, w = 64, b = 1600                          *    |
     * |-------------------------------------------------------------|
     */

    // uint32_t l; /* binary logarithm of lane size */
    // uint32_t w; /* lane size in bits */
    
    // 状态总宽度
    // 但在这份实现里实际存的是“字节数”而不是“bit 数”
    // 例如 b=200，实际上对应 1600 bit    
    uint32_t b; /* width of the state, b = r + c */
    
    // 吸收/挤出速率
    // 注释写成了 bit rate，但实现里实际用“字节”
    // 比如 SHAKE256 时 r=136，表示 136 字节 = 1088 bit    
    uint32_t r; /* bit rate, rate of a sponge function, length of one message block */
    
    // 容量
    // 同样，这里实现里存的是字节数
    // 比如 SHAKE256 时 c=64，表示 64 字节 = 512 bit    
    uint32_t c; /* capacity, r + c = b */

    // 轮数
    // 对 Keccak-f[1600]，l=6，所以 nr=24	
    uint32_t nr; /* round number, nr = 12 + 2l */

    // 输出摘要长度，单位是字节
    // 对 SHA3 固定长度
    // 对 SHAKE 则由用户传入 d/8 决定
    uint32_t md_size;   /* message digest size in bytes */

    // 当前是否处在吸收阶段
    // 1 表示 absorb
    // 0 表示 squeeze
    uint32_t absorbing; /* 1: absorbe; 0: squeeze */
}SHA3_CTX;

// 初始化固定输出 SHA3 上下文
int SHA3_Init(SHA3_CTX *c, SHA3_ALG alg);
// 增量吸收输入数据
int SHA3_Update(SHA3_CTX *c, const void *data, size_t len);
// 对最后一个块做 padding，完成最后一次 absorb，必要时继续 squeeze，输出结果
int SHA3_Final(unsigned char *md, SHA3_CTX *c);
// 一次性接口：Init + Update + Final
unsigned char *SHA3(SHA3_ALG alg, const unsigned char *data, size_t n, unsigned char *md);

/* Extendable-Output Functions: SHAKE128, SHAKE256 */
// 初始化 SHAKE128 / SHAKE256
// d 是想要输出的 bit 长度
int SHA3_XOF_Init(SHA3_CTX *c, SHA3_ALG alg, uint32_t d);
// 增量吸收输入数据，底层其实复用 SHA3_Update
int SHA3_XOF_Update(SHA3_CTX *c, const void *data, size_t len);
// 完成 padding 并输出 d/8 字节的 XOF 结果
int SHA3_XOF_Final(unsigned char *md, SHA3_CTX *c);
// 一次性接口：XOF_Init + XOF_Update + XOF_Final
unsigned char *SHA3_XOF(SHA3_ALG alg, const unsigned char *data, size_t n, unsigned char *md, uint32_t d);
#endif
