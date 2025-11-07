/**
 * @file ZLGkey.h
 * @author xfp23
 * @brief ECU 安全访问算法回调函数声明
 * @version 0.1
 * @date 2025-11-07
 * @copyright Copyright (c)
 */

#pragma once

#include "MicroSecurity.hpp"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport)
int ZLGKey(const uint8_t* seedArray,
           uint16_t seedLength,
           uint32_t securityLevel,
           const char* variantName,
           uint8_t* keyArray,
           uint16_t* keyLength);

#ifdef __cplusplus
}
#endif
