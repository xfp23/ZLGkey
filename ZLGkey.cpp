#include "ZLGKey.h"
#include "MicroSecurity.hpp"   // 确保包含安全算法头
#include <cstdio>
using namespace microsec;
using namespace std;
// 固定密钥
static const std::vector<uint8_t> g_Key = {
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};

extern "C" __declspec(dllexport)
int ZLGKey(const uint8_t* seedArray,
    uint16_t seedLength,
    uint32_t securityLevel,
    const char* variantName,
    uint8_t* keyArray,
    uint16_t* keyLength)
{

    if (!seedArray || seedLength == 0 || !keyArray || !keyLength) {
        return -1; 
    }

    MicroSecurity_Obj sec(g_Key);

    bool ok = false;

    switch (securityLevel)
    {
    case SecLevel_1:
        ok = sec.computeHMACTrunc(seedArray, seedLength, keyArray, 16);
        *keyLength = 16;
        break;

    case SecLevel_2:

        ok = sec.computeSHA256ConcatTrunc(seedArray, seedLength, keyArray, 32);
        *keyLength = 32;
        break;

    default:
        return -2; // 不支持的安全等级
    }

    if (!ok)
        return -3; // 算法执行失败（可能key为空）

    (void)variantName; 

    return 0; // 成功
}
