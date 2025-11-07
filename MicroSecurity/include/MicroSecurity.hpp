/**
 * @file MicroSecurity.hpp
 * @author xfp
 * @brief 通用安全算法接口（HMAC / SHA256）
 * @version 0.1
 * @date 2025-11-07
 * 
 * 提供以下功能：
 * - 设置/获取对称密钥
 * - 计算 HMAC-SHA256（可截断输出）
 * - 计算 SHA256(seed || key) 拼接模式（可截断）
 * - 提供独立的 SHA256 与 HMAC-SHA256 工具函数
 * 
 * 所有输出均为二进制字节，不包含 '\0' 结束符。
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
using namespace std;

namespace microsec {

/**
 * @brief 安全等级定义（仅作为标识用，可自定义扩展）
 */
typedef enum 
{
SecLevel_1 = 0x11,   ///< 低安全等级
SecLevel_2 = 0x71,   ///< 中安全等级
SecLevel_3 = 0xD1,   ///< 高安全等级
} SecLevel_t;


/**
 * @class MicroSecurity_Obj
 * @brief 安全算法对象类
 * 
 * 用于计算 HMAC / SHA256 等摘要算法。
 * 内部保存一个对称密钥 (m_key)，可在构造或后续设置。
 * 
 * 示例：
 * @code
 * using namespace microsec;
 * 
 * std::vector<uint8_t> key = {0x11, 0x22, 0x33, 0x44};
 * MicroSecurity_Obj sec(key);
 * 
 * uint8_t seed[] = {0xAA, 0xBB, 0xCC};
 * uint8_t out[16];
 * sec.computeHMACTrunc(seed, sizeof(seed), out, sizeof(out));
 * @endcode
 */
class MicroSecurity_Obj {
public:
/**
 * @brief 构造函数，可选择传入密钥
 * 
 * @param key 对称密钥（二进制字节序列，可为空）
 */
explicit MicroSecurity_Obj(const std::vector<uint8_t>& key = {});

~MicroSecurity_Obj();

/**
 * @brief 设置或替换当前使用的密钥
 * 
 * @param key 新的对称密钥（二进制字节）
 */
void setKey(const std::vector<uint8_t>& key);

/**
 * @brief 获取当前密钥
 * 
 * @return const std::vector<uint8_t>& 密钥引用
 */
const std::vector<uint8_t>& getKey() const;

/**
 * @brief 计算 HMAC-SHA256(K, seed)，并截取前 outTrunc 字节输出
 * 
 * @param seed     输入数据指针（例如随机数、挑战值）
 * @param seedLen  输入数据长度（字节）
 * @param out      输出缓冲区指针
 * @param outTrunc 输出长度（取前 outTrunc 字节，最大 32）
 * @return true    计算成功
 * @return false   密钥未设置或参数错误
 * 
 * @note 常用于 UDS 安全访问算法：Out = Trunc(HMAC(Key, Seed))
 */
bool computeHMACTrunc(const uint8_t* seed, size_t seedLen,
                        uint8_t* out, size_t outTrunc) const;

/**
 * @brief 计算 SHA256(seed || secret)，结果可截断
 * 
 * @param seed        种子数据（前半段）
 * @param seedLen     种子长度
 * @param out         输出缓冲区
 * @param outTrunc    输出截断长度（≤32）
 * @param extraSecret 额外密钥（可选，不传则使用内部密钥）
 * @return true       成功
 * @return false      参数错误
 * 
 * @note 用于实现如 "seed 与 key 拼接后取 SHA256" 的轻量认证逻辑。
 */
bool computeSHA256ConcatTrunc(const uint8_t* seed, size_t seedLen,
                                uint8_t* out, size_t outTrunc,
                                const std::vector<uint8_t>* extraSecret = nullptr) const;

/**
 * @brief 计算任意数据的 SHA256 哈希值
 * 
 * @param data   输入数据指针
 * @param len    输入数据长度（字节）
 * @param out32  输出 32 字节哈希结果
 * 
 * @note 静态函数，无需创建对象
 */
static void sha256(const uint8_t* data, size_t len, uint8_t out32[32]);

/**
 * @brief 计算 HMAC-SHA256(K, msg)
 * 
 * @param key     对称密钥指针
 * @param keylen  密钥长度
 * @param msg     输入消息指针
 * @param msglen  输入消息长度
 * @param out32   输出 32 字节 HMAC 值
 * 
 * @note 静态函数，无需创建对象
 */
static void hmac_sha256(const uint8_t* key, size_t keylen,
                        const uint8_t* msg, size_t msglen,
                        uint8_t out32[32]);

private:
std::vector<uint8_t> m_key; ///< 内部保存的对称密钥
};

} // namespace microsec
