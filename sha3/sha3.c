/*
 * @        file: sha3.c
 * @ description: implementation for the SHA3 Secure Hash Algorithm
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "sha3.h"

/*
1. b：置换宽度
b 是 KECCAK-p 置换的状态总宽度，单位是 bit。标准允许的取值是
{25, 50, 100, 200, 400, 800, 1600}。
SHA-3 / SHAKE 实际用的是 b = 1600。
你可以把它理解成：
整个内部状态一共有 1600 个 bit。

2. w：lane size
w = b / 25，表示每个 lane 的位宽。
当 b = 1600 时，w = 64。

直观上：
状态被分成 25 个 lane
每个 lane 是 64 bit
所以总共 25 × 64 = 1600 bit
这就是为什么实现里常用 25 个 uint64_t 来存状态。

3. l：lane size 的二进制对数
l = log2(w)。
当 w = 64 时，l = 6。
这个参数本身不直接参与吸收和输出，但它决定了轮数公式。

4. nr：轮数
nr 是 KECCAK-p[b, nr] 的 round 数。
对 SHA-3 使用的 KECCAK-p[1600,24]，有：
nr = 12 + 2l = 12 + 2×6 = 24。

所以：
一次完整的 Keccak-f[1600] 置换要做 24 轮
每一轮都执行 θ -> ρ -> π -> χ -> ι

5. A：state array
A 表示状态数组。标准把状态写成一个 5 × 5 × w 的三维数组，元素写成：
A[x, y, z]
其中：
x：0 到 4
y：0 到 4
z：0 到 w-1。
这就是你看到规范里总写 A[x,y,z] 的原因。

6. Lane(i,j)、Plane(j)、state string S
规范除了用三维数组，也允许把状态写成一个长度为 b 的 bit string S。
并定义了：
Lane(i,j)：固定 (x=i,y=j) 的整条 lane
Plane(j)：固定 y=j 的一个 plane
S：把所有 plane/lane 按固定顺序拼起来的状态字符串。
这几个概念的作用是：
帮你把“数学上的 3D 状态”映射到“程序里的线性内存”。

7. r：rate
r 是 sponge construction 里的 rate，表示：
每次 absorb 能处理多少输入 bit
每次 squeeze 能拿出多少输出 bit。
它决定：
输入块大小
输出块大小

8. c：capacity
c 是 sponge construction 里的 capacity。标准定义它为：
capacity = width - rate。
也就是：
c = b - r
所以 r 和 c 不是独立的；b 固定后，一个定了，另一个也就定了。
直觉上：
r 越大，吞吐越高
c 越大，安全裕量越高

9. f
f 是 sponge construction 的底层置换函数。
对 SHA-3 而言，它就是：
KECCAK-p[1600,24]，也就是通常说的 Keccak-f[1600]。

10. pad
pad 是 padding rule。
SHA-3 使用的是：pad10*1。
它的形式是：
1 || 0^j || 1
作用是把输入补到 r 的整数倍长度。

11. N
N 是进入 sponge 的输入串。
注意它不一定等于原始消息 M，因为实际进入 sponge 前要先做 域分离后缀拼接。
比如：
SHA3-256：N = M || 01
SHAKE256：N = M || 1111

12. M
M 是用户原始输入消息。
标准里所有 SHA-3 / SHAKE 都把原始输入写成 M。

13. d
d 有两个含义，取决于函数类型：
对 SHA3-224 / 256 / 384 / 512，d 表示 digest length
对 SHAKE128 / SHAKE256，d 表示 请求输出长度。
所以：
SHA3-256 里 d=256 是固定的
SHAKE256(M,d) 里 d 是你自己指定的

14. ir
ir 是 round index。
它只在 ι 步里用来选择 round constant。
也就是第 0 轮、第 1 轮……第 23 轮。

15. RC
RC 是 round constant。
每一轮最后的 ι 步都会把对应轮常量异或到状态里。
*/

/*
SHAKE128
c = 256
r = 1344
输出长度 d 可变
后缀: 1111。

SHAKE256
c = 512
r = 1088
输出长度 d 可变
后缀: 1111。
*/

//#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
// 是否打印每个 block 的输入数据
#define DUMP_BLOCK_DATA 1
// 是否打印每个 block 处理后的状态
#define DUMP_BLOCK_HASH 1
// 是否打印每一轮 round 的中间状态
#define DUMP_ROUND_DATA 1
// 是否打印 block XOR 进入 state 的过程
#define DUMP_SCHED_DATA 1
#else
#define DBG(...)
#define DUMP_BLOCK_DATA 0
#define DUMP_BLOCK_HASH 0
#define DUMP_ROUND_DATA 0
#define DUMP_SCHED_DATA 0
#endif

// 这一段是在解释 SHA3 固定输出模式的 delimiter + padding
// 注意：这里列的是 SHA3（后缀 01）的情况，不是 SHAKE（后缀 1111）
/*
 * FIPS-202, sec B.2:
 * |---------------|------------------------|
 * | Padding Bytes | Padding Message        |
 * |---------------|------------------------|
 * | q=1           | M||0x86                |
 * |---------------|------------------------|
 * | q=2           | M||0x0680              |
 * |---------------|------------------------|
 * | q>2           | M||0x06||0x00...||0x80 |
 * |---------------|------------------------|
 *
 * refer:
 *   https://cryptologie.net/article/387/byte-ordering-and-bit-numbering-in-keccak-and-sha-3/
 */

/*
 * SHA3 Delimiter + Padding
 *             01 + 10*1
 */

/*  q=1: 01 10 0001 <--reverse-- 1000 01 10, 1 byte, 0x86 */
#define SHA3_PADDING_STD1        0x86

/* q>=2: 01 10 0000....0000 0001 <--reverse-- 0000 01 10....1000 0000, 2 bytes, 0x06...0x80 */
#define SHA3_PADDING_STD2_BEGIN  0x06
#define SHA3_PADDING_STD2_END    0x80

// 这里是 SHAKE XOF 的 delimiter + padding
// 注意 SHAKE 的域分离后缀是 1111
/*
 * SHA3 XOF Delimiter + Padding
 *               1111 + 10*1
 */
/*  q=1: 1111 1001 <--reverse-- 1001 1111, 1 byte, 0x9F */
// 当 block 最后只剩 1 字节时，SHAKE 的合并 padding 字节是 0x9F
#define SHA3_PADDING_XOF1        0x9F

/* q>=2: 1111 1000....0000 0001 <--reverse 0001 1111....1000 0000, 2 bytes, 0x1F...0x80 */
// 当剩余至少 2 字节时，SHAKE 的起始 padding 字节是 0x1F
#define SHA3_PADDING_XOF2_BEGIN  0x1F
// SHAKE 的最后一个 padding 字节同样是 0x80
#define SHA3_PADDING_XOF2_END    0x80

/* ROTate Left (circular left shift) */
// 64 位循环左移
static uint64_t ROTL(uint64_t x, uint8_t shift)
{
    return (x << shift) | (x >> (64 - shift));
}

// theta 步：列奇偶扩散
static uint32_t theta(uint64_t A[5][5])
{
    // x 表示列，y 表示行
    uint32_t x, y;
    // 保存 theta 之后的新状态，避免原地覆盖影响计算    
    uint64_t Ap[5][5];
    // C[x] = 第 x 列 5 个 lane 的异或
    // D[x] = 由左右相邻列生成的扩散值    
    uint64_t C[5], D[5];

    // 全部清零，保证没有脏数据
    memset(C, 0, sizeof(C));
    memset(D, 0, sizeof(D));
    memset(Ap, 0, sizeof(Ap));

    for (x=0; x<5; x++)
    {
        // 因为这里数组是 A[y][x]
        // 所以固定 x、遍历 y，就是把同一列的 5 个 lane 异或起来
        // 对应 FIPS 里的 C[x]    
        C[x] = A[0][x] ^ A[1][x] ^ A[2][x] ^ A[3][x] ^ A[4][x];
    }

    for (x=0; x<5; x++)
    {
     /* D[x] = C[x-1]     ^ ROTR(C[x+1],     1) */
        // FIPS 中是 D[x] = C[x-1] xor ROT(C[x+1],1)
        // 这里用模 5 实现循环索引
        // 注释里写的是 ROTR，但代码实际做的是 ROTL(,1)
        // 在 Keccak 的 lane bit 编号约定下，写成左旋是常见实现形式     
        D[x] = C[(x+4)%5] ^ ROTL(C[(x+1)%5], 1);
    }

    for (y=0; y<5; y++)
    {
        for (x=0; x<5; x++)
        {
            // 把 D[x] 异或到整列的每个 lane 上        
            Ap[y][x] = A[y][x] ^ D[x];
        }
    }

    // 用新状态覆盖原状态
    memcpy(A, Ap, sizeof(Ap));
    return 0;
}

/* rotation constants, aka rotation offsets */
// rho 步使用的旋转偏移表
// 这些值比 64 大，但后面会对 64 取模
// 本质上对应 FIPS 中 rho 的偏移常量
static uint32_t Rp[5][5] =
{
    {   0,   1,  190,  28,  91},
    {  36, 300,    6,  55, 276},
    {   3,  10,  171, 153, 231},
    { 105,  45,   15,  21, 136},
    { 210,  66,  253, 120,  78}
};

// rho 步：对不同 lane 进行不同偏移量的循环旋转
static uint32_t rho(uint64_t A[5][5])
{
    // 保存 rho 后的新状态
    uint64_t Ap[5][5];
    // x,y 用于遍历 lane 位置
    // m 是临时变量，用来保存旧 x    
    uint32_t x, y, m;
    // rho 中的 24 步轨迹变量    
    uint32_t t;

    // 新状态先清零
    memset(Ap, 0, sizeof(Ap));
    /* let A'[0,0,z]=A[0,0,z] */
    // 这句实际上把第一行都复制了过去，而不只是 (0,0)
    // 但后面的循环会覆盖掉除 (0,0) 以外的其它位置
    // 所以最终等价于只让 (0,0) 不旋转
    // 这是个“写法有点粗，但结果正确”的实现细节    
    memcpy(Ap[0], A[0], sizeof(Ap[0]));

    /* let (x,y) = (1,0) */
    x = 1;
    y = 0;
    #if 0
    /* calculate directly */
    for (t=0; t<24; t++)
    {
        // 直接按规范中的公式计算偏移量    
        Ap[y][x] = ROTL(A[y][x], ((t+1)*(t+2)/2)%64);
        m = x;
        x = y;
        // 更新到下一个 lane 坐标        
        y = (2*m + 3*y) % 5;
    }
    #else
    /* look up table */
    for (t=0; t<24; t++)
    {
        // 使用查表方式对当前 lane 做循环左移
        // 比直接公式更直观，也更好读    
        Ap[y][x] = ROTL(A[y][x], Rp[y][x]%64);
        /* let (x,y) = (y,(2x+3y)%5) */
        m = x;
        x = y;
        y = (2*m+3*y) % 5;
    }
    #endif
    
    // 覆盖原状态
    memcpy(A, Ap, sizeof(Ap));
    return 0;
}

// pi 步：只改变 lane 的位置，不改变 lane 内部 bit 的顺序
static uint32_t pi(uint64_t A[5][5])
{
    // 保存 pi 之后的新状态
    uint64_t Ap[5][5];
    uint32_t x, y;

    // 清零
    memset(Ap, 0, sizeof(Ap));
    for (y=0; y<5; y++)
    {
        for (x=0; x<5; x++)
        {
            // 由于当前数组是 A[y][x] 布局
            // 这一行等价于 FIPS 里的 A'[x,y] = A[(x+3y) mod 5, x]
            // 本质上是在重排 25 个 lane 的位置        
            Ap[y][x] = A[x][(x+3*y)%5];
        }
    }

    // 覆盖原状态	
    memcpy(A, Ap, sizeof(Ap));
    return 0;
}

// chi 步：Keccak 的非线性步骤
// 按“行”处理，每一行 5 个 lane 相互作用
static uint32_t chi(uint64_t A[5][5])
{
    // 保存 chi 之后的新状态，避免原地改写出错
    uint64_t Ap[5][5];
    uint32_t x, y;

    // 清零
    memset(Ap, 0, sizeof(Ap));
    for (y=0; y<5; y++)
    {
        for (x=0; x<5; x++)
        {
            // 公式就是 Keccak 的 chi：
            // A[x,y] = A[x,y] xor ((not A[x+1,y]) and A[x+2,y])
            // 因为这里是 A[y][x] 布局，所以写法看起来会和规范索引顺序不同        
            Ap[y][x] = A[y][x] ^ ((~A[y][(x+1)%5]) & A[y][(x+2)%5]);
        }
    }
    // 覆盖原状态
    memcpy(A, Ap, sizeof(Ap));
    return 0;
}

static uint64_t RC[24] =
{
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
};
// iota 步使用的 24 个轮常量
// 对应 Keccak-f[1600] 每一轮最后异或到 A[0][0]
static uint32_t iota(uint64_t A[5][5], uint32_t i)
{
    A[0][0] = A[0][0] ^ RC[i];

    return 0;
}

// 初始化固定输出 SHA3 上下文
// 注意：这个函数故意不直接支持 SHAKE128/SHAKE256
int SHA3_Init(SHA3_CTX *c, SHA3_ALG alg)
{
    if (NULL == c)
    {
        // 上下文为空，返回参数错误    
        return ERR_INV_PARAM;
    }

    if ((alg == SHAKE128) || (alg == SHAKE256))
    {
        return ERR_INV_PARAM;
    }

    // 把上下文全部清零
    // 这一步会把 state/lane、last.buf、标志位全部归零
    // 对应海绵函数初始状态 S = 0^b
    memset(c, 0, sizeof(SHA3_CTX));

    /* bits */
    // c->l = 6;
    // c->w = 64; /* c->w = 2 ^ l */

    /* bytes */
    // 注意这里写的是 200 字节，不是 200 bit
    // 200 字节 = 1600 bit，也就是整个 Keccak-f[1600] 状态宽度    
    c->b = 200; /* 1600 bits, c->b = 25 * 2 ^ c->l; */
    c->alg = alg;
    switch (alg)
    {
        case SHA3_224:   /* SHA3-224(M) = KECCAK[448](M||01,224), FIPS-202, sec 6.1 */
            c->r  = 144;        /* 1152 bits */
            c->c  =  56;        /*  448 bits */
            c->md_size =  28;   /*  224 bits */
            break;
        case SHA3_256:   /* SHA3-256(M) = KECCAK[512](M||01,256), FIPS-202, sec 6.1 */
            c->r  = 136;        /* 1088 bits */
            c->c  =  64;        /*  512 bits */
            c->md_size =  32;   /*  256 bits */
            break;
        case SHA3_384:   /* SHA3-384(M) = KECCAK[768](M||01,384), FIPS-202, sec 6.1 */
            c->r  = 104;        /*  832 bits */
            c->c  =  96;        /*  768 bits */
            c->md_size =  48;   /*  384 bits */
            break;
        default: /* default Keccak setting: SHA3_512 */
        case SHA3_512:   /* SHA3-512(M) = KECCAK[1024](M||01,512), FIPS-202, sec 6.1 */
            c->r  =  72;        /*  576 bits */
            c->c  = 128;        /* 1024 bits */
            c->md_size =  64;   /*  512 bits */
            break;
    }

    // Keccak-f[1600] 固定 24 轮
    c->nr = 24; /* nr = 24 = 12 + 2 * l */
    // 初始化后处于吸收阶段    
    c->absorbing = 1; /* absorbing phase */
    
    // 初始化成功
    return ERR_OK;
}

// 这个宏是“打印被吸收数据与调度前后 state”的调试辅助
// 如果没打开 DUMP_SCHED_DATA，它就什么都不做
#if (DUMP_SCHED_DATA == 1)
#define sched_show_buffer(info,ptr,len) \
    DBG(info); \
    print_buffer((ptr),(len),"       ");
#else
#define sched_show_buffer(info,ptr,len)
#endif

#if (DUMP_ROUND_DATA == 1)
#define round_show_buffer(info) \
    DBG(info); \
    print_buffer(&ctx->lane[0][0], ctx->b, "       ");

static void dump_lane_buffer(uint64_t lane[5][5])
{
    uint32_t x, y;

    for (y=0; y<5; y++) /* row */
    {
        for (x=0; x<5; x++) /* col */
        {
            DBG("[%d, %d]: %016llx  ", x, y, lane[y][x]);
        }
        DBG("\n");
    }
    return;
}
#else
#define round_show_buffer(info)

static void dump_lane_buffer(uint64_t lane[5][5]) {}
#endif

// 把一个输入块变成“准备吸收到 state 中的 25 个 64-bit word”
// block 实际上指向外部输入块数据
static int SHA3_PrepareScheduleWord(SHA3_CTX *ctx, const uint64_t *block)
{
    uint32_t i;
    uint64_t *data;
    // temp[25] 对应整个 1600-bit 状态的 25 个 lane
    // 其中前 r/8 个 lane 装输入数据，后面 c/8 个 lane 填 0    
    uint64_t temp[25];

    if ((NULL == ctx) || (NULL == block))
    {
        return ERR_INV_PARAM;
    }

    for (i=0; i<ctx->b/8; i++)
    {
        // ctx->b = 200 字节
        // 所以 ctx->b / 8 = 25，正好是 25 个 64-bit lane    
        if (i<ctx->r/8)
        {
            // 前 r 字节的数据会被吸收进 state
            // 这里 block[i] 是 64 位块，使用 le64toh 转成主机字节序
            // 例如 SHAKE256 时 r=136 字节，r/8=17，所以只吸收前 17 个 lane        
            temp[i] = le64toh(block[i]);
        }
        else
        {
            // capacity 区域不直接吸收外部消息，所以填 0        
            temp[i] = 0x0;
        }
    }

    sched_show_buffer("Data to absorbed:\n", temp, ctx->b);
    sched_show_buffer("  SchedWord: [before]\n", &ctx->lane[0][0], ctx->b);

    /* initial S */
    // 把二维数组 lane 当成连续的 25 个 uint64_t 来访问    
    data = &ctx->lane[0][0];

    for (i=0; i<ctx->b/8; i++)
    {
        // sponge absorb 核心操作：
        // S = S xor (Pi || 0^c)    
        data[i] ^= temp[i];
    }

    sched_show_buffer("  SchedWord: [after]\n", &ctx->lane[0][0], ctx->b);

    return ERR_OK;
}

/* r bytes for each block */
// 处理一个 block
// 在 absorbing=1 时：先把 block XOR 进 state，再做 24 轮置换
// 在 absorbing=0 时：不再吸收 block，只做 24 轮置换，用于 squeeze
static int SHA3_ProcessBlock(SHA3_CTX *ctx, const void *block)
{
    uint32_t t;

    if ((NULL == ctx) || (ctx->absorbing && (NULL == block)))
    {
        // 如果在吸收阶段却没给 block，那是非法的
        // 但在挤出阶段 block 可以是 NULL    
        return ERR_INV_PARAM;
    }

#if (DUMP_BLOCK_DATA == 1)
    DBG("---------------------------------------------------------\n");
    DBG(" BLOCK DATA:\n");
    print_buffer(block, ctx->r, "       ");
#endif

    if (ctx->absorbing)
    {
        // 仅在吸收阶段，把当前块 XOR 进 state    
        SHA3_PrepareScheduleWord(ctx, block);
    }

    // 一共做 24 轮
    for (t=0; t<ctx->nr; t++)
    {
#if (DUMP_ROUND_DATA == 1)
        DBG("  Round #%02d:\n", t);
#endif
	// 第 1 步：theta
        theta(ctx->lane);
        round_show_buffer("After Theta:\n");
        
        // 第 2 步：rho
        rho(ctx->lane);
        round_show_buffer("  After Rho:\n");

        // 第 3 步：pi
        pi(ctx->lane);
        round_show_buffer("   After Pi:\n");

        // 第 4 步：chi
        chi(ctx->lane);
        round_show_buffer("  After Chi:\n");

        // 第 5 步：iota
        iota(ctx->lane, t);
        round_show_buffer(" After Iota:\n");
    }

    round_show_buffer("After Permutation:\n");
#if (DUMP_BLOCK_HASH == 1)
    DBG(" BLOCK HASH:\n");
    print_buffer(&ctx->lane[0][0], ctx->b, "       ");
#endif

    return ERR_OK;
}

// 增量吸收任意长度输入
// 这个函数只负责“完整块吸收”与“残留字节缓存”
// 不做 padding；padding 放在 Final 里
int SHA3_Update(SHA3_CTX *c, const void *data, size_t len)
{
    // 需要从新数据里拷多少字节去补满旧的残留块
    uint64_t copy_len = 0;

    if ((NULL == c) || (NULL == data))
    {
        return ERR_INV_PARAM;
    }

    /* has used data */
    if (c->last.used != 0)
    {    
        /* less than 1 block in total, combine data */
        // 如果上次已经有残留字节存在 last.buf 里        
        if (c->last.used + len < c->r)
        {
            // 新数据加进去后仍不满一个块，就只缓存        
            memcpy(&c->last.buf[c->last.used], data, len);
            // 更新已用字节数            
            c->last.used += len;

            // 先不做 block 处理
            return ERR_OK;
        }
        else /* more than 1 block */
        {
            /* process the block in context buffer */
            // 还差多少字节可以补满一个完整块            
            copy_len = c->r - c->last.used;
            // 从新数据里拿 copy_len 字节补满 last.buf            
            memcpy(&c->last.buf[c->last.used], data, copy_len);
            // 把拼好的完整块吸收并置换            
            SHA3_ProcessBlock(c, &c->last.buf);
            // 输入指针后移，跳过已经用掉的这部分数据
            data = (uint8_t *)data + copy_len;
            // 剩余长度减少            
            len -= copy_len;

            /* reset context buffer */
            // 清空 last.buf 的前 r 字节            
            memset(&c->last.buf[0], 0, c->r);
            // last.buf 现在没有残留字节了            
            c->last.used = 0;
        }
    }

    /* less than 1 block, copy to context buffer */
    if (len < c->r)
    {
        // 剩下的数据不足一个完整块，缓存起来    
        memcpy(&c->last.buf[c->last.used], data, len);
        // 更新缓存使用长度        
        c->last.used += len;

        return ERR_OK;
    }
    else
    {
        /* process data blocks */
        while (len >= c->r)
        {
            // 只要还有完整块，就直接一块块处理        
            SHA3_ProcessBlock(c, data);
            // 指针后移一个 rate block
            data = (uint8_t *)data + c->r;
            // 剩余长度减少            
            len -= c->r;
        }

        /* copy rest data to context buffer */
        // 最后剩下的不足一块的数据放到缓存里        
        memcpy(&c->last.buf[0], data, len);
        // 记录残留长度        
        c->last.used = len;
    }

    return ERR_OK;
}

// 完成最后一个块的 padding，做最终 absorb，随后从 state 中读出输出
// 这个函数既服务于 SHA3，也服务于 SHAKE
int SHA3_Final(unsigned char *md, SHA3_CTX *c)
{
    // 记录已经输出了多少字节
    // 主要用于 md_size > r 的情况，即需要多次 squeeze 的情况
    uint32_t md_size = 0; /* message digest size used */

    if ((NULL == c) || (NULL == md))
    {
        return ERR_INV_PARAM;
    }

    /* more than 2 bytes left */
    if (c->last.used <= (c->r - 2))
    {
        /* one more block */
        // 当前最后一个块里，至少还能放两个字节
        // 所以可以采用 “起始 padding 字节 + 中间若干 0 + 结尾 0x80” 的形式        
        if ((c->alg == SHAKE128) || (c->alg == SHAKE256)) /* XOFs */
        {
            // 对 SHAKE 来说，起始 padding 字节写 0x1F
            // 这对应域分离后缀 1111 + pad10*1 的前半部分        
            c->last.buf[c->last.used] = SHA3_PADDING_XOF2_BEGIN;
        }
        else
        {
            c->last.buf[c->last.used] = SHA3_PADDING_STD2_BEGIN;
        }
        // 消耗掉这个字节位置        
        c->last.used++;

        // 把中间剩余部分全部补 0
        // 注意最后 1 字节先不写，因为要放 0x80
        memset(&c->last.buf[c->last.used], 0, (c->r - 1) - c->last.used);
        // 当前位置跳到块的最后一个字节        
        c->last.used = c->r - 1;

        if ((c->alg == SHAKE128) || (c->alg == SHAKE256)) /* XOFs */
        {
            // SHAKE 最后一个字节写 0x80        
            c->last.buf[c->last.used] = SHA3_PADDING_XOF2_END;
        }
        else
        {
            // SHA3 最后一个字节同样写 0x80        
            c->last.buf[c->last.used] = SHA3_PADDING_STD2_END;
        }
        // 最后一个块现在已经补满        
        c->last.used++;
    }
    else /* if (c->last.used == (c->r - 1)) */ /* only 1 bytes left */
    {
        // 如果只剩最后 1 个字节位置可用
        // 就需要把 delimiter 和 pad10*1 合成一个字节写进去    
        if ((c->alg == SHAKE128) || (c->alg == SHAKE256)) /* XOFs */
        {
            // SHAKE 情况下写 0x9F        
            c->last.buf[c->last.used] = SHA3_PADDING_XOF1;
        }
        else
        {
            // SHA3 情况下写 0x86        
            c->last.buf[c->last.used] = SHA3_PADDING_STD1;
        }
        // 完成最后一个字节的写入        
        c->last.used++;
    }
    // 把补完 padding 的最后一块吸收进去，并执行 24 轮置换
    SHA3_ProcessBlock(c, &c->last.buf);
    // 清空残留块长度    
    c->last.used = 0;

    /* Absorbing Phase End */
    // 标记：吸收阶段结束，后面若还需要更多输出，就是 squeeze 阶段    
    c->absorbing = 0;

    dump_lane_buffer(c->lane);

    if (c->md_size <= c->r)
    {
        // 如果所需输出长度不超过一个 rate block
        // 就直接从 state 的前 md_size 字节拿出去
        // 对 SHA3_xxx 都是这种情况
        // 对某些较短的 SHAKE 输出也可能是这种情况    
        memcpy(md, &c->lane[0][0], c->md_size);
    }
    else
    {
        // 先拿第一个 rate block    
        memcpy(md, &c->lane[0][0], c->r);
        // 已经输出了 r 字节        
        md_size = c->r;

        /* squeeze */
        while (md_size < c->md_size)
        {
            // 由于 ctx->absorbing 已经是 0
            // 这里不会再吸收输入，只会纯做一次 Keccak-f[1600] 置换
            // 这正是 sponge 的 squeeze 操作        
            SHA3_ProcessBlock(c, NULL);
            if (c->md_size - md_size > c->r)
            {
                // 如果剩余需要的输出 still > r
                // 就整块拷出当前 state 前 r 字节            
                memcpy(&md[md_size], &c->lane[0][0], c->r);
                // 累加已输出字节数                
                md_size += c->r;
            }
            else
            {
                // 最后一次只拷出还缺的那部分字节            
                memcpy(&md[md_size], &c->lane[0][0], c->md_size - md_size);
                // 完成输出                
                md_size = c->md_size;
            }
        }
    }

    return ERR_OK;
}

unsigned char *SHA3(SHA3_ALG alg, const unsigned char *data, size_t n, unsigned char *md)
{
    // 在栈上创建一个上下文
    SHA3_CTX c;

    if ((NULL == data) || (NULL == md))
    {
        return NULL;
    }

    // 初始化，例如设置 r/c/md_size 等参数
    SHA3_Init(&c, alg);
    // 吸收整条消息    
    SHA3_Update(&c, data, n);
    // padding + 最后 absorb + 输出摘要   
    SHA3_Final(md, &c);

    // 返回输出缓冲区指针，便于链式使用
    return md;
}

/* d is d value for SHAKE128/SHAKE256, md_size = d / 8 */
// 初始化 XOF：SHAKE128 / SHAKE256
// d 是用户想要的输出长度（单位 bit）
int SHA3_XOF_Init(SHA3_CTX *c, SHA3_ALG alg, uint32_t d)
{
    if (NULL == c)
    {
        return ERR_INV_PARAM;
    }

    /* only for SHAKE128/SHAKE256 */
    if ((alg != SHAKE128) && (alg != SHAKE256))
    {
        // 这里只允许 SHAKE128 或 SHAKE256    
        return ERR_INV_PARAM;
    }

    /* using SHA3-512 as default */
    // 这里作者先用 SHA3_512 做一次“通用初始化”
    // 主要是借它把 context 清零，并把 b、nr、absorbing 等基础字段设好
    // 后面再把和 SHAKE 相关的参数覆盖掉    
    SHA3_Init(c, SHA3_512);

    // 把算法类型改成真正的 SHAKE128 或 SHAKE256
    c->alg = alg;

    /* update for SHAKE128/SHAKE256 */
    switch(alg)
    {
        case SHAKE128:  /* SHAKE128(M,d) = KECCAK[256](M||1111,d), FIPS-202, sec 6.2 */
            c->r = 168; /* 1344 bits */
            c->c = 32;  /*  256 bits */
            // 输出长度按用户传入 d（bit）转换成字节            
            c->md_size = d / 8;
            break;
        default:
        case SHAKE256:  /* SHAKE256(M,d) = KECCAK[512](M||1111,d), FIPS-202, sec 6.2 */
            c->r = 136; /* 1088 bits */
            c->c = 64;  /*  512 bits */
            // 输出长度按用户传入 d（bit）转换成字节            
            c->md_size = d / 8;
            break;
    }

    return ERR_OK;
}

int SHA3_XOF_Update(SHA3_CTX *c, const void *data, size_t len)
{
    // XOF 的 Update 和普通 SHA3 没区别
    // 都只是 absorb 消息数据
    return SHA3_Update(c, data, len);
}

int SHA3_XOF_Final(unsigned char *md, SHA3_CTX *c)
{
    // XOF 的 Final 也复用同一个 Final
    // 区别体现在 ctx->alg 和 ctx->md_size 上
    // Final 内部会根据 alg 自动选择 SHAKE 的 padding
    return SHA3_Final(md, c);
}

// 一次性 XOF 接口：适用于 SHAKE128 / SHAKE256
unsigned char *SHA3_XOF(SHA3_ALG alg, const unsigned char *data, size_t n, unsigned char *md, uint32_t d)
{
    // 栈上上下文
    SHA3_CTX c;

    if ((NULL == data) || (NULL == md))
    {
        return NULL;
    }

    /* only for SHAKE128/SHAKE256 */
    if ((alg != SHAKE128) && (alg != SHAKE256))
    {
        return NULL;
    }

    // 初始化 SHAKE 参数，特别是 r/c/md_size
    SHA3_XOF_Init(&c, alg, d);
    // 吸收输入消息    
    SHA3_XOF_Update(&c, data, n);
    // padding + 最后 absorb + squeeze 指定长度输出    
    SHA3_XOF_Final(md, &c);

    return md;
}
