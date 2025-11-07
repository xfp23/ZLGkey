/**
 * @file ZLGkey.hpp
 * @author xfp23
 * @brief 
 * @version 0.1
 * @date 2025-11-07
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#pragma once

#include "MicroSecurity.hpp"
#include "stdint.h"

/**
 * @brief  ECU 安全访问算法回调函数（ZCANPro 调用此函数生成 Key）
 *
 * @param[in]  seedArray       指向 ECU 下发的 Seed 数据缓冲区
 * @param[in]  seedLength      Seed 的字节长度
 * @param[in]  securityLevel   安全访问等级（如 0x11、0x71 等）
 * @param[in]  variantName     ECU 变种名称（ZCANPro 配置文件中填写的字符串）
 *
 * @param[out] keyArray        指向用于存放计算结果 Key 的缓冲区
 * @param[out] keyLength       返回的 Key 长度（单位：字节）
 *
 * @return int  返回 0 表示计算成功，非 0 表示错误
 *
 * @note
 *  - 本函数由 ZCANPro 在解锁过程中自动调用。
 *  - 用户应根据具体 ECU 的安全算法实现 Key 计算逻辑。
 *  - 若支持多个 ECU 型号，可通过 variantName 或 securityLevel 区分。
 */
extern int ZLGKey(const uint8_t* seedArray,uint16_t seedLength,uint32_t securityLevel,const char* variantName,uint8_t* keyArray,uint16_t* keyLength);
