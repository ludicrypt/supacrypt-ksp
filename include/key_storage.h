// key_storage.h - Key storage management for Supacrypt KSP
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <windows.h>
#include <ncrypt.h>
#include <string>
#include <memory>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <chrono>

namespace supacrypt
{
namespace ksp
{

// Forward declarations
class GrpcBackendClient;

/// @brief Key metadata information
struct KeyMetadata
{
    std::wstring keyId;
    std::wstring algorithm;
    DWORD keySize;
    DWORD keyUsage;
    bool isPersistent;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point lastUsed;
    std::wstring friendlyName;
    std::vector<BYTE> publicKeyBlob;
    std::unordered_map<std::wstring, std::vector<BYTE>> properties;
};

/// @brief Key storage context
struct KeyContext
{
    NCRYPT_KEY_HANDLE handle;
    std::wstring keyId;
    std::wstring algorithm;
    DWORD keySpec;
    DWORD flags;
    bool isFinalized;
    std::unique_ptr<KeyMetadata> metadata;
    mutable std::mutex mutex;

    KeyContext(NCRYPT_KEY_HANDLE h, const std::wstring& id, const std::wstring& alg)
        : handle(h), keyId(id), algorithm(alg), keySpec(0), flags(0), isFinalized(false)
    {
        metadata = std::make_unique<KeyMetadata>();
        metadata->keyId = keyId;
        metadata->algorithm = algorithm;
    }
};

/// @brief Enumeration state for key enumeration
struct KeyEnumState
{
    std::vector<std::wstring> keyNames;
    size_t currentIndex;
    std::wstring scope;
    DWORD flags;
    
    KeyEnumState() : currentIndex(0), flags(0) {}
};

/// @brief Key storage manager for Windows CNG KSP
class KeyStorageManager
{
public:
    /// @brief Constructor
    /// @param backendClient gRPC backend client
    explicit KeyStorageManager(std::shared_ptr<GrpcBackendClient> backendClient);

    /// @brief Destructor
    ~KeyStorageManager();

    // Disable copy and move
    KeyStorageManager(const KeyStorageManager&) = delete;
    KeyStorageManager& operator=(const KeyStorageManager&) = delete;
    KeyStorageManager(KeyStorageManager&&) = delete;
    KeyStorageManager& operator=(KeyStorageManager&&) = delete;

    /// @brief Initialize key storage
    /// @return NTSTATUS success or error code
    NTSTATUS Initialize();

    /// @brief Shutdown key storage
    void Shutdown();

    /// @brief Create new key
    /// @param handle Key handle
    /// @param algorithm Algorithm identifier
    /// @param keyName Key name (optional)
    /// @param keySpec Legacy key specification
    /// @param flags Creation flags
    /// @return NTSTATUS success or error code
    NTSTATUS CreateKey(
        NCRYPT_KEY_HANDLE handle,
        const std::wstring& algorithm,
        const std::wstring& keyName,
        DWORD keySpec,
        DWORD flags);

    /// @brief Open existing key
    /// @param handle Key handle
    /// @param keyName Key name
    /// @param keySpec Legacy key specification
    /// @param flags Open flags
    /// @return NTSTATUS success or error code
    NTSTATUS OpenKey(
        NCRYPT_KEY_HANDLE handle,
        const std::wstring& keyName,
        DWORD keySpec,
        DWORD flags);

    /// @brief Delete key
    /// @param handle Key handle
    /// @param flags Delete flags
    /// @return NTSTATUS success or error code
    NTSTATUS DeleteKey(
        NCRYPT_KEY_HANDLE handle,
        DWORD flags);

    /// @brief Finalize key creation
    /// @param handle Key handle
    /// @param flags Finalization flags
    /// @return NTSTATUS success or error code
    NTSTATUS FinalizeKey(
        NCRYPT_KEY_HANDLE handle,
        DWORD flags);

    /// @brief Get key property
    /// @param handle Key handle
    /// @param property Property name
    /// @param buffer Output buffer
    /// @param bufferSize Size of output buffer
    /// @param resultSize Actual output size
    /// @param flags Property flags
    /// @return NTSTATUS success or error code
    NTSTATUS GetKeyProperty(
        NCRYPT_KEY_HANDLE handle,
        const std::wstring& property,
        PBYTE buffer,
        DWORD bufferSize,
        DWORD* resultSize,
        DWORD flags);

    /// @brief Set key property
    /// @param handle Key handle
    /// @param property Property name
    /// @param data Input data
    /// @param dataSize Size of input data
    /// @param flags Property flags
    /// @return NTSTATUS success or error code
    NTSTATUS SetKeyProperty(
        NCRYPT_KEY_HANDLE handle,
        const std::wstring& property,
        PBYTE data,
        DWORD dataSize,
        DWORD flags);

    /// @brief Export key
    /// @param handle Key handle
    /// @param exportKey Export key handle (optional)
    /// @param blobType Blob type
    /// @param parameters Parameter list
    /// @param buffer Output buffer
    /// @param bufferSize Size of output buffer
    /// @param resultSize Actual output size
    /// @param flags Export flags
    /// @return NTSTATUS success or error code
    NTSTATUS ExportKey(
        NCRYPT_KEY_HANDLE handle,
        NCRYPT_KEY_HANDLE exportKey,
        const std::wstring& blobType,
        NCryptBufferDesc* parameters,
        PBYTE buffer,
        DWORD bufferSize,
        DWORD* resultSize,
        DWORD flags);

    /// @brief Import key
    /// @param handle Key handle
    /// @param importKey Import key handle (optional)
    /// @param blobType Blob type
    /// @param parameters Parameter list
    /// @param keyData Key data
    /// @param keyDataSize Size of key data
    /// @param flags Import flags
    /// @return NTSTATUS success or error code
    NTSTATUS ImportKey(
        NCRYPT_KEY_HANDLE handle,
        NCRYPT_KEY_HANDLE importKey,
        const std::wstring& blobType,
        NCryptBufferDesc* parameters,
        PBYTE keyData,
        DWORD keyDataSize,
        DWORD flags);

    /// @brief Enumerate keys
    /// @param scope Scope (optional)
    /// @param keyName Pointer to key name
    /// @param enumState Enumeration state
    /// @param flags Enumeration flags
    /// @return NTSTATUS success or error code
    NTSTATUS EnumerateKeys(
        const std::wstring& scope,
        NCryptKeyName** keyName,
        VOID** enumState,
        DWORD flags);

    /// @brief Free enumeration state
    /// @param enumState Enumeration state
    /// @return NTSTATUS success or error code
    NTSTATUS FreeKeyEnumeration(VOID* enumState);

    /// @brief Free key name structure
    /// @param keyName Key name structure
    /// @return NTSTATUS success or error code
    NTSTATUS FreeKeyName(NCryptKeyName* keyName);

    /// @brief Get key context
    /// @param handle Key handle
    /// @return Pointer to key context or nullptr
    std::shared_ptr<KeyContext> GetKeyContext(NCRYPT_KEY_HANDLE handle);

    /// @brief Register key handle
    /// @param handle Key handle
    /// @param keyId Key identifier
    /// @param algorithm Algorithm
    /// @return NTSTATUS success or error code
    NTSTATUS RegisterKeyHandle(
        NCRYPT_KEY_HANDLE handle,
        const std::wstring& keyId,
        const std::wstring& algorithm);

    /// @brief Unregister key handle
    /// @param handle Key handle
    void UnregisterKeyHandle(NCRYPT_KEY_HANDLE handle);

    /// @brief Check if key exists
    /// @param keyName Key name
    /// @return true if exists, false otherwise
    bool KeyExists(const std::wstring& keyName);

    /// @brief Generate unique key name
    /// @param prefix Prefix for key name
    /// @return Unique key name
    std::wstring GenerateUniqueKeyName(const std::wstring& prefix = L"supacrypt-key");

private:
    /// @brief Load key metadata from backend
    /// @param keyId Key identifier
    /// @param metadata Metadata to populate
    /// @return NTSTATUS success or error code
    NTSTATUS LoadKeyMetadata(const std::wstring& keyId, KeyMetadata& metadata);

    /// @brief Save key metadata to backend
    /// @param metadata Metadata to save
    /// @return NTSTATUS success or error code
    NTSTATUS SaveKeyMetadata(const KeyMetadata& metadata);

    /// @brief Convert algorithm name to CNG format
    /// @param algorithm Algorithm name
    /// @return CNG algorithm identifier
    std::wstring MapAlgorithmToCng(const std::wstring& algorithm);

    /// @brief Convert algorithm name from CNG format
    /// @param cngAlgorithm CNG algorithm identifier
    /// @return Backend algorithm name
    std::wstring MapAlgorithmFromCng(const std::wstring& cngAlgorithm);

    /// @brief Validate key name
    /// @param keyName Key name to validate
    /// @return true if valid, false otherwise
    bool ValidateKeyName(const std::wstring& keyName);

    /// @brief Generate key identifier
    /// @param keyName Key name
    /// @param algorithm Algorithm
    /// @return Unique key identifier
    std::wstring GenerateKeyId(const std::wstring& keyName, const std::wstring& algorithm);

    /// @brief Update key last used timestamp
    /// @param handle Key handle
    void UpdateKeyLastUsed(NCRYPT_KEY_HANDLE handle);

    /// @brief Get key size for algorithm
    /// @param algorithm Algorithm identifier
    /// @return Default key size in bits
    DWORD GetDefaultKeySize(const std::wstring& algorithm);

    /// @brief Convert property name to backend format
    /// @param property CNG property name
    /// @return Backend property name
    std::string ConvertPropertyName(const std::wstring& property);

    /// @brief Convert property value to backend format
    /// @param property Property name
    /// @param data Property data
    /// @param size Property data size
    /// @return Backend property value
    std::vector<BYTE> ConvertPropertyValue(
        const std::wstring& property,
        PBYTE data,
        DWORD size);

private:
    mutable std::mutex m_mutex;
    bool m_initialized;
    
    // Backend client
    std::shared_ptr<GrpcBackendClient> m_backendClient;
    
    // Key contexts
    std::unordered_map<NCRYPT_KEY_HANDLE, std::shared_ptr<KeyContext>> m_keyContexts;
    
    // Key name mapping
    std::unordered_map<std::wstring, NCRYPT_KEY_HANDLE> m_keyNameMap;
    
    // Algorithm mappings
    std::unordered_map<std::wstring, std::wstring> m_algorithmMap;
    std::unordered_map<std::wstring, DWORD> m_algorithmKeySizes;
    
    // Configuration
    std::wstring m_keyStorePath;
    bool m_enablePersistence;
    size_t m_maxCachedKeys;
    std::chrono::seconds m_keyTimeout;
};

} // namespace ksp
} // namespace supacrypt