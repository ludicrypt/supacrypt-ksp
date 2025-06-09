// algorithm_provider.h - Algorithm implementations for Supacrypt KSP
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <windows.h>
#include <ncrypt.h>
#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <unordered_set>

namespace supacrypt
{
namespace ksp
{

// Forward declarations
class GrpcBackendClient;
class KeyStorageManager;

/// @brief Padding information for RSA operations
struct RsaPaddingInfo
{
    DWORD paddingScheme;  // NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PAD_PSS_FLAG, NCRYPT_PAD_OAEP_FLAG
    std::wstring hashAlgorithm;
    std::wstring mgfHashAlgorithm;  // For PSS and OAEP
    DWORD saltLength;  // For PSS
    std::vector<BYTE> label;  // For OAEP
};

/// @brief ECC signature format information
struct EccSignatureInfo
{
    DWORD format;  // NCRYPT_ECDSA_SIGNATURE_FORMAT, etc.
    std::wstring hashAlgorithm;
};

/// @brief Key derivation information
struct KeyDerivationInfo
{
    std::wstring kdfAlgorithm;
    std::vector<BYTE> keyDerivationParameters;
    DWORD derivedKeyLength;
};

/// @brief Algorithm capability information
struct AlgorithmCapability
{
    std::wstring algorithmId;
    std::wstring algorithmClass;  // NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE, etc.
    std::vector<DWORD> supportedKeySizes;
    std::unordered_set<DWORD> supportedOperations;  // NCRYPT_ALLOW_* flags
    std::vector<std::wstring> supportedPadding;
    std::vector<std::wstring> supportedHashAlgorithms;
    DWORD defaultKeySize;
    bool supportsKeyGeneration;
    bool supportsKeyImport;
    bool supportsKeyExport;
};

/// @brief Algorithm provider for cryptographic operations
class AlgorithmProvider
{
public:
    /// @brief Constructor
    /// @param backendClient gRPC backend client
    /// @param keyStorage Key storage manager
    explicit AlgorithmProvider(
        std::shared_ptr<GrpcBackendClient> backendClient,
        std::shared_ptr<KeyStorageManager> keyStorage);

    /// @brief Destructor
    ~AlgorithmProvider();

    // Disable copy and move
    AlgorithmProvider(const AlgorithmProvider&) = delete;
    AlgorithmProvider& operator=(const AlgorithmProvider&) = delete;
    AlgorithmProvider(AlgorithmProvider&&) = delete;
    AlgorithmProvider& operator=(AlgorithmProvider&&) = delete;

    /// @brief Initialize algorithm provider
    /// @return NTSTATUS success or error code
    NTSTATUS Initialize();

    /// @brief Shutdown algorithm provider
    void Shutdown();

    /// @brief Sign hash
    /// @param keyHandle Key handle
    /// @param paddingInfo Padding information
    /// @param hashValue Hash value to sign
    /// @param hashSize Size of hash value
    /// @param signature Buffer for signature
    /// @param signatureSize Size of signature buffer
    /// @param resultSize Actual signature size
    /// @param flags Signing flags
    /// @return NTSTATUS success or error code
    NTSTATUS SignHash(
        NCRYPT_KEY_HANDLE keyHandle,
        VOID* paddingInfo,
        PBYTE hashValue,
        DWORD hashSize,
        PBYTE signature,
        DWORD signatureSize,
        DWORD* resultSize,
        DWORD flags);

    /// @brief Verify signature
    /// @param keyHandle Key handle
    /// @param paddingInfo Padding information
    /// @param hashValue Hash value
    /// @param hashSize Size of hash value
    /// @param signature Signature to verify
    /// @param signatureSize Size of signature
    /// @param flags Verification flags
    /// @return NTSTATUS success or error code
    NTSTATUS VerifySignature(
        NCRYPT_KEY_HANDLE keyHandle,
        VOID* paddingInfo,
        PBYTE hashValue,
        DWORD hashSize,
        PBYTE signature,
        DWORD signatureSize,
        DWORD flags);

    /// @brief Encrypt data
    /// @param keyHandle Key handle
    /// @param input Input data
    /// @param inputSize Size of input data
    /// @param paddingInfo Padding information
    /// @param output Output buffer
    /// @param outputSize Size of output buffer
    /// @param resultSize Actual output size
    /// @param flags Encryption flags
    /// @return NTSTATUS success or error code
    NTSTATUS Encrypt(
        NCRYPT_KEY_HANDLE keyHandle,
        PBYTE input,
        DWORD inputSize,
        VOID* paddingInfo,
        PBYTE output,
        DWORD outputSize,
        DWORD* resultSize,
        DWORD flags);

    /// @brief Decrypt data
    /// @param keyHandle Key handle
    /// @param input Input data
    /// @param inputSize Size of input data
    /// @param paddingInfo Padding information
    /// @param output Output buffer
    /// @param outputSize Size of output buffer
    /// @param resultSize Actual output size
    /// @param flags Decryption flags
    /// @return NTSTATUS success or error code
    NTSTATUS Decrypt(
        NCRYPT_KEY_HANDLE keyHandle,
        PBYTE input,
        DWORD inputSize,
        VOID* paddingInfo,
        PBYTE output,
        DWORD outputSize,
        DWORD* resultSize,
        DWORD flags);

    /// @brief Perform key agreement (ECDH)
    /// @param privateKey Private key handle
    /// @param publicKey Public key handle
    /// @param sharedSecret Buffer for shared secret
    /// @param sharedSecretSize Size of shared secret buffer
    /// @param resultSize Actual shared secret size
    /// @param flags Agreement flags
    /// @return NTSTATUS success or error code
    NTSTATUS KeyAgreement(
        NCRYPT_KEY_HANDLE privateKey,
        NCRYPT_KEY_HANDLE publicKey,
        PBYTE sharedSecret,
        DWORD sharedSecretSize,
        DWORD* resultSize,
        DWORD flags);

    /// @brief Derive key material
    /// @param baseKey Base key handle
    /// @param derivationInfo Derivation parameters
    /// @param derivedKey Buffer for derived key
    /// @param derivedKeySize Size of derived key buffer
    /// @param resultSize Actual derived key size
    /// @param flags Derivation flags
    /// @return NTSTATUS success or error code
    NTSTATUS DeriveKey(
        NCRYPT_KEY_HANDLE baseKey,
        const KeyDerivationInfo& derivationInfo,
        PBYTE derivedKey,
        DWORD derivedKeySize,
        DWORD* resultSize,
        DWORD flags);

    /// @brief Generate key pair
    /// @param algorithm Algorithm identifier
    /// @param keySize Key size in bits
    /// @param keyHandle Key handle for new key
    /// @param flags Generation flags
    /// @return NTSTATUS success or error code
    NTSTATUS GenerateKeyPair(
        const std::wstring& algorithm,
        DWORD keySize,
        NCRYPT_KEY_HANDLE keyHandle,
        DWORD flags);

    /// @brief Get algorithm capability
    /// @param algorithm Algorithm identifier
    /// @return Pointer to capability information or nullptr
    const AlgorithmCapability* GetAlgorithmCapability(const std::wstring& algorithm) const;

    /// @brief Check if algorithm is supported
    /// @param algorithm Algorithm identifier
    /// @return true if supported, false otherwise
    bool IsAlgorithmSupported(const std::wstring& algorithm) const;

    /// @brief Check if operation is supported for algorithm
    /// @param algorithm Algorithm identifier
    /// @param operation Operation flag
    /// @return true if supported, false otherwise
    bool IsOperationSupported(const std::wstring& algorithm, DWORD operation) const;

    /// @brief Get supported algorithms
    /// @return Vector of supported algorithm identifiers
    std::vector<std::wstring> GetSupportedAlgorithms() const;

    /// @brief Get default key size for algorithm
    /// @param algorithm Algorithm identifier
    /// @return Default key size in bits, 0 if unknown
    DWORD GetDefaultKeySize(const std::wstring& algorithm) const;

    /// @brief Validate key size for algorithm
    /// @param algorithm Algorithm identifier
    /// @param keySize Key size to validate
    /// @return true if valid, false otherwise
    bool ValidateKeySize(const std::wstring& algorithm, DWORD keySize) const;

private:
    /// @brief Initialize algorithm capabilities
    /// @return NTSTATUS success or error code
    NTSTATUS InitializeCapabilities();

    /// @brief Parse RSA padding information
    /// @param paddingInfo Padding info pointer
    /// @param algorithm Algorithm identifier
    /// @param parsedInfo Parsed padding information
    /// @return NTSTATUS success or error code
    NTSTATUS ParseRsaPaddingInfo(
        VOID* paddingInfo,
        const std::wstring& algorithm,
        RsaPaddingInfo& parsedInfo);

    /// @brief Parse ECC signature information
    /// @param paddingInfo Padding info pointer
    /// @param algorithm Algorithm identifier
    /// @param signatureInfo Parsed signature information
    /// @return NTSTATUS success or error code
    NTSTATUS ParseEccSignatureInfo(
        VOID* paddingInfo,
        const std::wstring& algorithm,
        EccSignatureInfo& signatureInfo);

    /// @brief Convert CNG algorithm to backend format
    /// @param cngAlgorithm CNG algorithm identifier
    /// @return Backend algorithm identifier
    std::string ConvertAlgorithmToBackend(const std::wstring& cngAlgorithm);

    /// @brief Convert CNG padding to backend format
    /// @param paddingInfo Padding information
    /// @param algorithm Algorithm identifier
    /// @return Backend padding specification
    std::string ConvertPaddingToBackend(
        const RsaPaddingInfo& paddingInfo,
        const std::wstring& algorithm);

    /// @brief Convert hash algorithm to backend format
    /// @param hashAlgorithm Hash algorithm identifier
    /// @return Backend hash algorithm identifier
    std::string ConvertHashAlgorithmToBackend(const std::wstring& hashAlgorithm);

    /// @brief Validate operation parameters
    /// @param keyHandle Key handle
    /// @param operation Operation type
    /// @param algorithm Algorithm identifier
    /// @return NTSTATUS success or error code
    NTSTATUS ValidateOperationParameters(
        NCRYPT_KEY_HANDLE keyHandle,
        const std::wstring& operation,
        const std::wstring& algorithm);

    /// @brief Get key algorithm from handle
    /// @param keyHandle Key handle
    /// @return Algorithm identifier
    std::wstring GetKeyAlgorithm(NCRYPT_KEY_HANDLE keyHandle);

    /// @brief Calculate signature size
    /// @param algorithm Algorithm identifier
    /// @param keySize Key size in bits
    /// @param paddingInfo Padding information
    /// @return Signature size in bytes
    DWORD CalculateSignatureSize(
        const std::wstring& algorithm,
        DWORD keySize,
        const RsaPaddingInfo* paddingInfo = nullptr);

    /// @brief Calculate encryption output size
    /// @param algorithm Algorithm identifier
    /// @param keySize Key size in bits
    /// @param inputSize Input data size
    /// @param paddingInfo Padding information
    /// @return Output size in bytes
    DWORD CalculateEncryptionSize(
        const std::wstring& algorithm,
        DWORD keySize,
        DWORD inputSize,
        const RsaPaddingInfo* paddingInfo = nullptr);

private:
    bool m_initialized;
    
    // Component dependencies
    std::shared_ptr<GrpcBackendClient> m_backendClient;
    std::shared_ptr<KeyStorageManager> m_keyStorage;
    
    // Algorithm capabilities
    std::unordered_map<std::wstring, AlgorithmCapability> m_capabilities;
    std::unordered_set<std::wstring> m_supportedAlgorithms;
    
    // Algorithm mappings
    std::unordered_map<std::wstring, std::string> m_algorithmMap;
    std::unordered_map<std::wstring, std::string> m_hashAlgorithmMap;
    std::unordered_map<DWORD, std::string> m_paddingMap;
    
    // Default configurations
    std::unordered_map<std::wstring, DWORD> m_defaultKeySizes;
    std::unordered_map<std::wstring, std::vector<DWORD>> m_validKeySizes;
};

} // namespace ksp
} // namespace supacrypt