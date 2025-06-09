// ksp_provider.h - Main KSP provider interface for Supacrypt
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <windows.h>
#include <ncrypt.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <mutex>

namespace supacrypt
{
namespace ksp
{

// Forward declarations
class GrpcBackendClient;
class KeyStorageManager;
class AlgorithmProvider;
class ErrorHandler;

/// @brief Main Windows CNG Key Storage Provider implementation
class WindowsKspProvider
{
public:
    /// @brief Constructor
    WindowsKspProvider();

    /// @brief Destructor
    ~WindowsKspProvider();

    // Disable copy and move
    WindowsKspProvider(const WindowsKspProvider&) = delete;
    WindowsKspProvider& operator=(const WindowsKspProvider&) = delete;
    WindowsKspProvider(WindowsKspProvider&&) = delete;
    WindowsKspProvider& operator=(WindowsKspProvider&&) = delete;

    /// @brief Initialize the KSP provider
    /// @return NTSTATUS success or error code
    NTSTATUS Initialize();

    /// @brief Shutdown the KSP provider
    void Shutdown();

    /// @brief Get provider interface
    /// @param pszInterface Interface identifier
    /// @param ppFunctionTable Pointer to function table
    /// @param dwFlags Flags (reserved)
    /// @return NTSTATUS success or error code
    NTSTATUS GetInterface(
        LPCWSTR pszInterface,
        NCRYPT_INTERFACE_FN_TABLE** ppFunctionTable,
        DWORD dwFlags);

    /// @brief Open provider handle
    /// @param phProvider Pointer to provider handle
    /// @param pszProviderName Provider name
    /// @param dwFlags Open flags
    /// @return NTSTATUS success or error code
    NTSTATUS OpenProvider(
        NCRYPT_PROV_HANDLE* phProvider,
        LPCWSTR pszProviderName,
        DWORD dwFlags);

    /// @brief Close provider handle
    /// @param hProvider Provider handle
    /// @param dwFlags Close flags
    /// @return NTSTATUS success or error code
    NTSTATUS CloseProvider(
        NCRYPT_PROV_HANDLE hProvider,
        DWORD dwFlags);

    /// @brief Create new key
    /// @param hProvider Provider handle
    /// @param phKey Pointer to key handle
    /// @param pszAlgId Algorithm identifier
    /// @param pszKeyName Key name (optional)
    /// @param dwLegacyKeySpec Legacy key specification
    /// @param dwFlags Creation flags
    /// @return NTSTATUS success or error code
    NTSTATUS CreateKey(
        NCRYPT_PROV_HANDLE hProvider,
        NCRYPT_KEY_HANDLE* phKey,
        LPCWSTR pszAlgId,
        LPCWSTR pszKeyName,
        DWORD dwLegacyKeySpec,
        DWORD dwFlags);

    /// @brief Open existing key
    /// @param hProvider Provider handle
    /// @param phKey Pointer to key handle
    /// @param pszKeyName Key name
    /// @param dwLegacyKeySpec Legacy key specification
    /// @param dwFlags Open flags
    /// @return NTSTATUS success or error code
    NTSTATUS OpenKey(
        NCRYPT_PROV_HANDLE hProvider,
        NCRYPT_KEY_HANDLE* phKey,
        LPCWSTR pszKeyName,
        DWORD dwLegacyKeySpec,
        DWORD dwFlags);

    /// @brief Delete key
    /// @param hKey Key handle
    /// @param dwFlags Delete flags
    /// @return NTSTATUS success or error code
    NTSTATUS DeleteKey(
        NCRYPT_KEY_HANDLE hKey,
        DWORD dwFlags);

    /// @brief Finalize key creation
    /// @param hKey Key handle
    /// @param dwFlags Finalization flags
    /// @return NTSTATUS success or error code
    NTSTATUS FinalizeKey(
        NCRYPT_KEY_HANDLE hKey,
        DWORD dwFlags);

    /// @brief Sign data
    /// @param hKey Key handle
    /// @param pPaddingInfo Padding information
    /// @param pbHashValue Hash value to sign
    /// @param cbHashValue Size of hash value
    /// @param pbSignature Buffer for signature
    /// @param cbSignature Size of signature buffer
    /// @param pcbResult Actual signature size
    /// @param dwFlags Signing flags
    /// @return NTSTATUS success or error code
    NTSTATUS SignHash(
        NCRYPT_KEY_HANDLE hKey,
        VOID* pPaddingInfo,
        PBYTE pbHashValue,
        DWORD cbHashValue,
        PBYTE pbSignature,
        DWORD cbSignature,
        DWORD* pcbResult,
        DWORD dwFlags);

    /// @brief Verify signature
    /// @param hKey Key handle
    /// @param pPaddingInfo Padding information
    /// @param pbHashValue Hash value
    /// @param cbHashValue Size of hash value
    /// @param pbSignature Signature to verify
    /// @param cbSignature Size of signature
    /// @param dwFlags Verification flags
    /// @return NTSTATUS success or error code
    NTSTATUS VerifySignature(
        NCRYPT_KEY_HANDLE hKey,
        VOID* pPaddingInfo,
        PBYTE pbHashValue,
        DWORD cbHashValue,
        PBYTE pbSignature,
        DWORD cbSignature,
        DWORD dwFlags);

    /// @brief Encrypt data
    /// @param hKey Key handle
    /// @param pbInput Input data
    /// @param cbInput Size of input data
    /// @param pPaddingInfo Padding information
    /// @param pbOutput Output buffer
    /// @param cbOutput Size of output buffer
    /// @param pcbResult Actual output size
    /// @param dwFlags Encryption flags
    /// @return NTSTATUS success or error code
    NTSTATUS Encrypt(
        NCRYPT_KEY_HANDLE hKey,
        PBYTE pbInput,
        DWORD cbInput,
        VOID* pPaddingInfo,
        PBYTE pbOutput,
        DWORD cbOutput,
        DWORD* pcbResult,
        DWORD dwFlags);

    /// @brief Decrypt data
    /// @param hKey Key handle
    /// @param pbInput Input data
    /// @param cbInput Size of input data
    /// @param pPaddingInfo Padding information
    /// @param pbOutput Output buffer
    /// @param cbOutput Size of output buffer
    /// @param pcbResult Actual output size
    /// @param dwFlags Decryption flags
    /// @return NTSTATUS success or error code
    NTSTATUS Decrypt(
        NCRYPT_KEY_HANDLE hKey,
        PBYTE pbInput,
        DWORD cbInput,
        VOID* pPaddingInfo,
        PBYTE pbOutput,
        DWORD cbOutput,
        DWORD* pcbResult,
        DWORD dwFlags);

    /// @brief Get key property
    /// @param hKey Key handle
    /// @param pszProperty Property name
    /// @param pbOutput Output buffer
    /// @param cbOutput Size of output buffer
    /// @param pcbResult Actual output size
    /// @param dwFlags Property flags
    /// @return NTSTATUS success or error code
    NTSTATUS GetKeyProperty(
        NCRYPT_KEY_HANDLE hKey,
        LPCWSTR pszProperty,
        PBYTE pbOutput,
        DWORD cbOutput,
        DWORD* pcbResult,
        DWORD dwFlags);

    /// @brief Set key property
    /// @param hKey Key handle
    /// @param pszProperty Property name
    /// @param pbInput Input data
    /// @param cbInput Size of input data
    /// @param dwFlags Property flags
    /// @return NTSTATUS success or error code
    NTSTATUS SetKeyProperty(
        NCRYPT_KEY_HANDLE hKey,
        LPCWSTR pszProperty,
        PBYTE pbInput,
        DWORD cbInput,
        DWORD dwFlags);

    /// @brief Export key
    /// @param hKey Key handle
    /// @param hExportKey Export key handle (optional)
    /// @param pszBlobType Blob type
    /// @param pParameterList Parameter list
    /// @param pbOutput Output buffer
    /// @param cbOutput Size of output buffer
    /// @param pcbResult Actual output size
    /// @param dwFlags Export flags
    /// @return NTSTATUS success or error code
    NTSTATUS ExportKey(
        NCRYPT_KEY_HANDLE hKey,
        NCRYPT_KEY_HANDLE hExportKey,
        LPCWSTR pszBlobType,
        NCryptBufferDesc* pParameterList,
        PBYTE pbOutput,
        DWORD cbOutput,
        DWORD* pcbResult,
        DWORD dwFlags);

    /// @brief Import key
    /// @param hProvider Provider handle
    /// @param hImportKey Import key handle (optional)
    /// @param pszBlobType Blob type
    /// @param pParameterList Parameter list
    /// @param phKey Pointer to key handle
    /// @param pbData Key data
    /// @param cbData Size of key data
    /// @param dwFlags Import flags
    /// @return NTSTATUS success or error code
    NTSTATUS ImportKey(
        NCRYPT_PROV_HANDLE hProvider,
        NCRYPT_KEY_HANDLE hImportKey,
        LPCWSTR pszBlobType,
        NCryptBufferDesc* pParameterList,
        NCRYPT_KEY_HANDLE* phKey,
        PBYTE pbData,
        DWORD cbData,
        DWORD dwFlags);

    /// @brief Enumerate keys
    /// @param hProvider Provider handle
    /// @param pszScope Scope (optional)
    /// @param ppKeyName Pointer to key name
    /// @param ppEnumState Enumeration state
    /// @param dwFlags Enumeration flags
    /// @return NTSTATUS success or error code
    NTSTATUS EnumKeys(
        NCRYPT_PROV_HANDLE hProvider,
        LPCWSTR pszScope,
        NCryptKeyName** ppKeyName,
        VOID** ppEnumState,
        DWORD dwFlags);

    /// @brief Free enumeration state
    /// @param pEnumState Enumeration state
    /// @return NTSTATUS success or error code
    NTSTATUS FreeKeyEnum(VOID* pEnumState);

    /// @brief Free key name structure
    /// @param pKeyName Key name structure
    /// @return NTSTATUS success or error code
    NTSTATUS FreeKeyName(NCryptKeyName* pKeyName);

    /// @brief Get singleton instance
    /// @return Reference to singleton instance
    static WindowsKspProvider& GetInstance();

private:
    /// @brief Initialize backend connection
    /// @return NTSTATUS success or error code
    NTSTATUS InitializeBackend();

    /// @brief Initialize algorithm providers
    /// @return NTSTATUS success or error code
    NTSTATUS InitializeAlgorithms();

    /// @brief Validate handle
    /// @param handle Handle to validate
    /// @return true if valid, false otherwise
    bool IsValidHandle(NCRYPT_HANDLE handle) const;

    /// @brief Generate unique handle
    /// @return New unique handle
    NCRYPT_HANDLE GenerateHandle();

    /// @brief Add provider handle to tracking
    /// @param handle Provider handle
    void AddProviderHandle(NCRYPT_PROV_HANDLE handle);

    /// @brief Remove provider handle from tracking
    /// @param handle Provider handle
    void RemoveProviderHandle(NCRYPT_PROV_HANDLE handle);

    /// @brief Add key handle to tracking
    /// @param handle Key handle
    /// @param keyName Key name
    void AddKeyHandle(NCRYPT_KEY_HANDLE handle, const std::wstring& keyName);

    /// @brief Remove key handle from tracking
    /// @param handle Key handle
    void RemoveKeyHandle(NCRYPT_KEY_HANDLE handle);

private:
    mutable std::mutex m_mutex;
    bool m_initialized;
    
    // Component managers
    std::unique_ptr<GrpcBackendClient> m_backendClient;
    std::unique_ptr<KeyStorageManager> m_keyStorage;
    std::unique_ptr<AlgorithmProvider> m_algorithms;
    std::unique_ptr<ErrorHandler> m_errorHandler;

    // Handle tracking
    std::unordered_map<NCRYPT_PROV_HANDLE, bool> m_providerHandles;
    std::unordered_map<NCRYPT_KEY_HANDLE, std::wstring> m_keyHandles;
    ULONG_PTR m_nextHandle;

    // Provider configuration
    std::wstring m_providerName;
    std::wstring m_backendEndpoint;
    std::wstring m_certificatePath;
    
    // Singleton instance
    static std::unique_ptr<WindowsKspProvider> s_instance;
    static std::once_flag s_instanceFlag;
};

} // namespace ksp
} // namespace supacrypt