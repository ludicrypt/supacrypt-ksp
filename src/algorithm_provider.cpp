// algorithm_provider.cpp - Algorithm provider implementation for Supacrypt KSP
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#include "algorithm_provider.h"
#include "grpc_backend.h"
#include "key_storage.h"
#include "error_handling.h"
#include "logging.h"

#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <algorithm>
#include <unordered_set>

namespace supacrypt
{
namespace ksp
{

AlgorithmProvider::AlgorithmProvider(
    std::shared_ptr<GrpcBackendClient> backendClient,
    std::shared_ptr<KeyStorageManager> keyStorage)
    : m_initialized(false)
    , m_backendClient(backendClient)
    , m_keyStorage(keyStorage)
{
    LogFunctionEntry();
    LogInfo(L"AlgorithmProvider created");
}

AlgorithmProvider::~AlgorithmProvider()
{
    LogFunctionEntry();
    Shutdown();
}

NTSTATUS AlgorithmProvider::Initialize()
{
    LogFunctionEntry();
    
    if (m_initialized)
    {
        LogInfo(L"Algorithm provider already initialized");
        return STATUS_SUCCESS;
    }

    try
    {
        LogInfo(L"Initializing algorithm provider...");

        // Validate dependencies
        if (!m_backendClient)
        {
            SET_KSP_ERROR(KspErrorCode::InvalidState, L"Backend client not available");
            return KSP_TO_NTSTATUS(KspErrorCode::InvalidState);
        }

        if (!m_keyStorage)
        {
            SET_KSP_ERROR(KspErrorCode::InvalidState, L"Key storage not available");
            return KSP_TO_NTSTATUS(KspErrorCode::InvalidState);
        }

        // Initialize algorithm capabilities
        NTSTATUS status = InitializeCapabilities();
        if (!NT_SUCCESS(status))
        {
            LogError(L"Failed to initialize algorithm capabilities");
            return status;
        }

        m_initialized = true;
        LogInfo(L"Algorithm provider initialized successfully");
        LogInfo(L"Supported algorithms: %zu", m_supportedAlgorithms.size());
        
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception during algorithm provider initialization");
        LogError(L"Exception in AlgorithmProvider::Initialize: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

void AlgorithmProvider::Shutdown()
{
    LogFunctionEntry();
    
    if (!m_initialized)
    {
        LogDebug(L"Algorithm provider not initialized, nothing to shutdown");
        return;
    }

    try
    {
        LogInfo(L"Shutting down algorithm provider...");

        // Clear all mappings and capabilities
        m_capabilities.clear();
        m_supportedAlgorithms.clear();
        m_algorithmMap.clear();
        m_hashAlgorithmMap.clear();
        m_paddingMap.clear();
        m_defaultKeySizes.clear();
        m_validKeySizes.clear();

        m_initialized = false;
        LogInfo(L"Algorithm provider shutdown completed");
    }
    catch (const std::exception& e)
    {
        LogError(L"Exception during algorithm provider shutdown: %hs", e.what());
    }
    
    LogFunctionExit();
}

NTSTATUS AlgorithmProvider::SignHash(
    NCRYPT_KEY_HANDLE keyHandle,
    VOID* paddingInfo,
    PBYTE hashValue,
    DWORD hashSize,
    PBYTE signature,
    DWORD signatureSize,
    DWORD* resultSize,
    DWORD flags)
{
    LogFunctionEntry();
    
    if (!m_initialized)
    {
        SET_KSP_ERROR(KspErrorCode::ProviderNotInitialized, L"Algorithm provider not initialized");
        return KSP_TO_NTSTATUS(KspErrorCode::ProviderNotInitialized);
    }

    try
    {
        LogInfo(L"Signing hash for key handle: 0x%p", keyHandle);

        // Get key context and algorithm
        auto keyContext = m_keyStorage->GetKeyContext(keyHandle);
        if (!keyContext)
        {
            SET_KSP_ERROR(KspErrorCode::InvalidKeyHandle, L"Invalid key handle");
            return KSP_TO_NTSTATUS(KspErrorCode::InvalidKeyHandle);
        }

        std::lock_guard<std::mutex> keyLock(keyContext->mutex);

        if (!keyContext->isFinalized)
        {
            SET_KSP_ERROR(KspErrorCode::KeyNotFinalized, L"Key not finalized");
            return KSP_TO_NTSTATUS(KspErrorCode::KeyNotFinalized);
        }

        std::wstring algorithm = keyContext->algorithm;
        
        // Validate operation is supported
        NTSTATUS status = ValidateOperationParameters(keyHandle, L"sign", algorithm);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        // Parse padding information
        RsaPaddingInfo rsaPadding{};
        EccSignatureInfo eccInfo{};
        
        if (algorithm.find(L"RSA") != std::wstring::npos)
        {
            status = ParseRsaPaddingInfo(paddingInfo, algorithm, rsaPadding);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }
        else if (algorithm.find(L"ECDSA") != std::wstring::npos)
        {
            status = ParseEccSignatureInfo(paddingInfo, algorithm, eccInfo);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }

        // Calculate signature size if not provided
        DWORD expectedSize = CalculateSignatureSize(algorithm, keyContext->metadata->keySize, &rsaPadding);
        
        *resultSize = expectedSize;
        
        if (!signature)
        {
            // Size query
            LogDebug(L"Signature size query, returning: %lu", expectedSize);
            return STATUS_SUCCESS;
        }
        
        if (signatureSize < expectedSize)
        {
            SET_KSP_ERROR(KspErrorCode::BufferTooSmall, L"Signature buffer too small");
            return KSP_TO_NTSTATUS(KspErrorCode::BufferTooSmall);
        }

        // Convert parameters for backend
        std::string backendAlgorithm = ConvertAlgorithmToBackend(algorithm);
        std::string backendPadding = ConvertPaddingToBackend(rsaPadding, algorithm);
        std::string backendHashAlg = ConvertHashAlgorithmToBackend(
            algorithm.find(L"RSA") != std::wstring::npos ? rsaPadding.hashAlgorithm : eccInfo.hashAlgorithm);

        // Call backend to sign
        std::vector<uint8_t> hashVector(hashValue, hashValue + hashSize);
        
        auto signResult = m_backendClient->SignData(
            std::string(keyContext->keyId.begin(), keyContext->keyId.end()),
            backendAlgorithm,
            hashVector,
            backendPadding,
            backendHashAlg);
            
        if (!signResult.success)
        {
            SET_KSP_ERROR(KspErrorCode::SigningFailed, L"Backend signing operation failed");
            LogError(L"Backend SignData failed: %hs", signResult.errorMessage.c_str());
            return KSP_TO_NTSTATUS(KspErrorCode::SigningFailed);
        }

        // Copy signature data
        const auto& signatureData = signResult.response;
        if (signatureData.size() > signatureSize)
        {
            SET_KSP_ERROR(KspErrorCode::InternalError, L"Backend returned signature larger than expected");
            return KSP_TO_NTSTATUS(KspErrorCode::InternalError);
        }

        memcpy(signature, signatureData.data(), signatureData.size());
        *resultSize = static_cast<DWORD>(signatureData.size());

        LogInfo(L"Hash signed successfully, signature size: %lu", *resultSize);
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception signing hash");
        LogError(L"Exception in SignHash: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS AlgorithmProvider::VerifySignature(
    NCRYPT_KEY_HANDLE keyHandle,
    VOID* paddingInfo,
    PBYTE hashValue,
    DWORD hashSize,
    PBYTE signature,
    DWORD signatureSize,
    DWORD flags)
{
    LogFunctionEntry();
    
    if (!m_initialized)
    {
        SET_KSP_ERROR(KspErrorCode::ProviderNotInitialized, L"Algorithm provider not initialized");
        return KSP_TO_NTSTATUS(KspErrorCode::ProviderNotInitialized);
    }

    try
    {
        LogInfo(L"Verifying signature for key handle: 0x%p", keyHandle);

        // Get key context and algorithm
        auto keyContext = m_keyStorage->GetKeyContext(keyHandle);
        if (!keyContext)
        {
            SET_KSP_ERROR(KspErrorCode::InvalidKeyHandle, L"Invalid key handle");
            return KSP_TO_NTSTATUS(KspErrorCode::InvalidKeyHandle);
        }

        std::lock_guard<std::mutex> keyLock(keyContext->mutex);

        if (!keyContext->isFinalized)
        {
            SET_KSP_ERROR(KspErrorCode::KeyNotFinalized, L"Key not finalized");
            return KSP_TO_NTSTATUS(KspErrorCode::KeyNotFinalized);
        }

        std::wstring algorithm = keyContext->algorithm;
        
        // Validate operation is supported
        NTSTATUS status = ValidateOperationParameters(keyHandle, L"verify", algorithm);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        // Parse padding information
        RsaPaddingInfo rsaPadding{};
        EccSignatureInfo eccInfo{};
        
        if (algorithm.find(L"RSA") != std::wstring::npos)
        {
            status = ParseRsaPaddingInfo(paddingInfo, algorithm, rsaPadding);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }
        else if (algorithm.find(L"ECDSA") != std::wstring::npos)
        {
            status = ParseEccSignatureInfo(paddingInfo, algorithm, eccInfo);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }

        // Convert parameters for backend
        std::string backendAlgorithm = ConvertAlgorithmToBackend(algorithm);
        std::string backendPadding = ConvertPaddingToBackend(rsaPadding, algorithm);
        std::string backendHashAlg = ConvertHashAlgorithmToBackend(
            algorithm.find(L"RSA") != std::wstring::npos ? rsaPadding.hashAlgorithm : eccInfo.hashAlgorithm);

        // Call backend to verify
        std::vector<uint8_t> hashVector(hashValue, hashValue + hashSize);
        std::vector<uint8_t> signatureVector(signature, signature + signatureSize);
        
        auto verifyResult = m_backendClient->VerifySignature(
            std::string(keyContext->keyId.begin(), keyContext->keyId.end()),
            backendAlgorithm,
            hashVector,
            signatureVector,
            backendPadding,
            backendHashAlg);
            
        if (!verifyResult.success)
        {
            SET_KSP_ERROR(KspErrorCode::VerificationFailed, L"Backend verification operation failed");
            LogError(L"Backend VerifySignature failed: %hs", verifyResult.errorMessage.c_str());
            return KSP_TO_NTSTATUS(KspErrorCode::VerificationFailed);
        }

        // Check verification result
        if (!verifyResult.response)
        {
            SET_KSP_ERROR(KspErrorCode::InvalidSignature, L"Signature verification failed");
            LogWarning(L"Signature verification failed for key: 0x%p", keyHandle);
            return KSP_TO_NTSTATUS(KspErrorCode::InvalidSignature);
        }

        LogInfo(L"Signature verified successfully");
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception verifying signature");
        LogError(L"Exception in VerifySignature: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS AlgorithmProvider::Encrypt(
    NCRYPT_KEY_HANDLE keyHandle,
    PBYTE input,
    DWORD inputSize,
    VOID* paddingInfo,
    PBYTE output,
    DWORD outputSize,
    DWORD* resultSize,
    DWORD flags)
{
    LogFunctionEntry();
    
    if (!m_initialized)
    {
        SET_KSP_ERROR(KspErrorCode::ProviderNotInitialized, L"Algorithm provider not initialized");
        return KSP_TO_NTSTATUS(KspErrorCode::ProviderNotInitialized);
    }

    try
    {
        LogInfo(L"Encrypting data for key handle: 0x%p", keyHandle);

        // Get key context and algorithm
        auto keyContext = m_keyStorage->GetKeyContext(keyHandle);
        if (!keyContext)
        {
            SET_KSP_ERROR(KspErrorCode::InvalidKeyHandle, L"Invalid key handle");
            return KSP_TO_NTSTATUS(KspErrorCode::InvalidKeyHandle);
        }

        std::lock_guard<std::mutex> keyLock(keyContext->mutex);

        if (!keyContext->isFinalized)
        {
            SET_KSP_ERROR(KspErrorCode::KeyNotFinalized, L"Key not finalized");
            return KSP_TO_NTSTATUS(KspErrorCode::KeyNotFinalized);
        }

        std::wstring algorithm = keyContext->algorithm;
        
        // Only RSA supports encryption in this implementation
        if (algorithm.find(L"RSA") == std::wstring::npos)
        {
            SET_KSP_ERROR(KspErrorCode::AlgorithmNotSupported, L"Encryption not supported for algorithm");
            return KSP_TO_NTSTATUS(KspErrorCode::AlgorithmNotSupported);
        }

        // Validate operation is supported
        NTSTATUS status = ValidateOperationParameters(keyHandle, L"encrypt", algorithm);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        // Parse padding information
        RsaPaddingInfo rsaPadding{};
        status = ParseRsaPaddingInfo(paddingInfo, algorithm, rsaPadding);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        // Calculate output size
        DWORD expectedSize = CalculateEncryptionSize(algorithm, keyContext->metadata->keySize, 
                                                    inputSize, &rsaPadding);
        
        *resultSize = expectedSize;
        
        if (!output)
        {
            // Size query
            LogDebug(L"Encryption size query, returning: %lu", expectedSize);
            return STATUS_SUCCESS;
        }
        
        if (outputSize < expectedSize)
        {
            SET_KSP_ERROR(KspErrorCode::BufferTooSmall, L"Output buffer too small");
            return KSP_TO_NTSTATUS(KspErrorCode::BufferTooSmall);
        }

        // Convert parameters for backend
        std::string backendAlgorithm = ConvertAlgorithmToBackend(algorithm);
        std::string backendPadding = ConvertPaddingToBackend(rsaPadding, algorithm);

        // Call backend to encrypt
        std::vector<uint8_t> inputVector(input, input + inputSize);
        
        auto encryptResult = m_backendClient->EncryptData(
            std::string(keyContext->keyId.begin(), keyContext->keyId.end()),
            backendAlgorithm,
            inputVector,
            backendPadding);
            
        if (!encryptResult.success)
        {
            SET_KSP_ERROR(KspErrorCode::EncryptionFailed, L"Backend encryption operation failed");
            LogError(L"Backend EncryptData failed: %hs", encryptResult.errorMessage.c_str());
            return KSP_TO_NTSTATUS(KspErrorCode::EncryptionFailed);
        }

        // Copy encrypted data
        const auto& encryptedData = encryptResult.response;
        if (encryptedData.size() > outputSize)
        {
            SET_KSP_ERROR(KspErrorCode::InternalError, L"Backend returned ciphertext larger than expected");
            return KSP_TO_NTSTATUS(KspErrorCode::InternalError);
        }

        memcpy(output, encryptedData.data(), encryptedData.size());
        *resultSize = static_cast<DWORD>(encryptedData.size());

        LogInfo(L"Data encrypted successfully, output size: %lu", *resultSize);
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception encrypting data");
        LogError(L"Exception in Encrypt: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS AlgorithmProvider::Decrypt(
    NCRYPT_KEY_HANDLE keyHandle,
    PBYTE input,
    DWORD inputSize,
    VOID* paddingInfo,
    PBYTE output,
    DWORD outputSize,
    DWORD* resultSize,
    DWORD flags)
{
    LogFunctionEntry();
    
    if (!m_initialized)
    {
        SET_KSP_ERROR(KspErrorCode::ProviderNotInitialized, L"Algorithm provider not initialized");
        return KSP_TO_NTSTATUS(KspErrorCode::ProviderNotInitialized);
    }

    try
    {
        LogInfo(L"Decrypting data for key handle: 0x%p", keyHandle);

        // Get key context and algorithm
        auto keyContext = m_keyStorage->GetKeyContext(keyHandle);
        if (!keyContext)
        {
            SET_KSP_ERROR(KspErrorCode::InvalidKeyHandle, L"Invalid key handle");
            return KSP_TO_NTSTATUS(KspErrorCode::InvalidKeyHandle);
        }

        std::lock_guard<std::mutex> keyLock(keyContext->mutex);

        if (!keyContext->isFinalized)
        {
            SET_KSP_ERROR(KspErrorCode::KeyNotFinalized, L"Key not finalized");
            return KSP_TO_NTSTATUS(KspErrorCode::KeyNotFinalized);
        }

        std::wstring algorithm = keyContext->algorithm;
        
        // Only RSA supports decryption in this implementation
        if (algorithm.find(L"RSA") == std::wstring::npos)
        {
            SET_KSP_ERROR(KspErrorCode::AlgorithmNotSupported, L"Decryption not supported for algorithm");
            return KSP_TO_NTSTATUS(KspErrorCode::AlgorithmNotSupported);
        }

        // Validate operation is supported
        NTSTATUS status = ValidateOperationParameters(keyHandle, L"decrypt", algorithm);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        // Parse padding information
        RsaPaddingInfo rsaPadding{};
        status = ParseRsaPaddingInfo(paddingInfo, algorithm, rsaPadding);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        // Convert parameters for backend
        std::string backendAlgorithm = ConvertAlgorithmToBackend(algorithm);
        std::string backendPadding = ConvertPaddingToBackend(rsaPadding, algorithm);

        // Call backend to decrypt
        std::vector<uint8_t> inputVector(input, input + inputSize);
        
        auto decryptResult = m_backendClient->DecryptData(
            std::string(keyContext->keyId.begin(), keyContext->keyId.end()),
            backendAlgorithm,
            inputVector,
            backendPadding);
            
        if (!decryptResult.success)
        {
            SET_KSP_ERROR(KspErrorCode::DecryptionFailed, L"Backend decryption operation failed");
            LogError(L"Backend DecryptData failed: %hs", decryptResult.errorMessage.c_str());
            return KSP_TO_NTSTATUS(KspErrorCode::DecryptionFailed);
        }

        // Check output buffer size
        const auto& decryptedData = decryptResult.response;
        *resultSize = static_cast<DWORD>(decryptedData.size());
        
        if (!output)
        {
            // Size query
            LogDebug(L"Decryption size query, returning: %lu", *resultSize);
            return STATUS_SUCCESS;
        }
        
        if (outputSize < decryptedData.size())
        {
            SET_KSP_ERROR(KspErrorCode::BufferTooSmall, L"Output buffer too small");
            return KSP_TO_NTSTATUS(KspErrorCode::BufferTooSmall);
        }

        // Copy decrypted data
        memcpy(output, decryptedData.data(), decryptedData.size());

        LogInfo(L"Data decrypted successfully, output size: %lu", *resultSize);
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception decrypting data");
        LogError(L"Exception in Decrypt: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

// Algorithm capability and validation methods

const AlgorithmCapability* AlgorithmProvider::GetAlgorithmCapability(const std::wstring& algorithm) const
{
    auto iter = m_capabilities.find(algorithm);
    if (iter != m_capabilities.end())
    {
        return &iter->second;
    }
    return nullptr;
}

bool AlgorithmProvider::IsAlgorithmSupported(const std::wstring& algorithm) const
{
    return m_supportedAlgorithms.find(algorithm) != m_supportedAlgorithms.end();
}

bool AlgorithmProvider::IsOperationSupported(const std::wstring& algorithm, DWORD operation) const
{
    auto capability = GetAlgorithmCapability(algorithm);
    if (!capability)
    {
        return false;
    }
    
    return capability->supportedOperations.find(operation) != capability->supportedOperations.end();
}

std::vector<std::wstring> AlgorithmProvider::GetSupportedAlgorithms() const
{
    std::vector<std::wstring> algorithms;
    algorithms.reserve(m_supportedAlgorithms.size());
    
    for (const auto& alg : m_supportedAlgorithms)
    {
        algorithms.push_back(alg);
    }
    
    return algorithms;
}

DWORD AlgorithmProvider::GetDefaultKeySize(const std::wstring& algorithm) const
{
    auto iter = m_defaultKeySizes.find(algorithm);
    if (iter != m_defaultKeySizes.end())
    {
        return iter->second;
    }
    
    // Fallback defaults
    if (algorithm.find(L"RSA") != std::wstring::npos)
    {
        return 2048;
    }
    else if (algorithm.find(L"ECDSA") != std::wstring::npos || 
             algorithm.find(L"ECDH") != std::wstring::npos)
    {
        return 256; // P-256
    }
    
    return 0; // Unknown
}

bool AlgorithmProvider::ValidateKeySize(const std::wstring& algorithm, DWORD keySize) const
{
    auto iter = m_validKeySizes.find(algorithm);
    if (iter != m_validKeySizes.end())
    {
        const auto& validSizes = iter->second;
        return std::find(validSizes.begin(), validSizes.end(), keySize) != validSizes.end();
    }
    
    // Basic validation for common algorithms
    if (algorithm.find(L"RSA") != std::wstring::npos)
    {
        return keySize >= 1024 && keySize <= 16384 && (keySize % 256) == 0;
    }
    else if (algorithm.find(L"ECDSA") != std::wstring::npos || 
             algorithm.find(L"ECDH") != std::wstring::npos)
    {
        return keySize == 256 || keySize == 384 || keySize == 521;
    }
    
    return false;
}

// Private initialization and helper methods

NTSTATUS AlgorithmProvider::InitializeCapabilities()
{
    LogFunctionEntry();
    
    try
    {
        // Initialize RSA capabilities
        {
            AlgorithmCapability rsaCap;
            rsaCap.algorithmId = NCRYPT_RSA_ALGORITHM;
            rsaCap.algorithmClass = NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE;
            rsaCap.supportedKeySizes = {1024, 2048, 3072, 4096};
            rsaCap.supportedOperations = {
                NCRYPT_ALLOW_SIGNING_FLAG,
                NCRYPT_ALLOW_DECRYPT_FLAG,
                NCRYPT_ALLOW_KEY_AGREEMENT_FLAG
            };
            rsaCap.supportedPadding = {L"PKCS1", L"PSS", L"OAEP"};
            rsaCap.supportedHashAlgorithms = {L"SHA1", L"SHA256", L"SHA384", L"SHA512"};
            rsaCap.defaultKeySize = 2048;
            rsaCap.supportsKeyGeneration = true;
            rsaCap.supportsKeyImport = true;
            rsaCap.supportsKeyExport = true;
            
            m_capabilities[NCRYPT_RSA_ALGORITHM] = rsaCap;
            m_supportedAlgorithms.insert(NCRYPT_RSA_ALGORITHM);
        }

        // Initialize ECDSA P-256 capabilities
        {
            AlgorithmCapability ecdsaCap;
            ecdsaCap.algorithmId = NCRYPT_ECDSA_P256_ALGORITHM;
            ecdsaCap.algorithmClass = NCRYPT_SIGNATURE_INTERFACE;
            ecdsaCap.supportedKeySizes = {256};
            ecdsaCap.supportedOperations = {NCRYPT_ALLOW_SIGNING_FLAG};
            ecdsaCap.supportedPadding = {L"None"};
            ecdsaCap.supportedHashAlgorithms = {L"SHA256", L"SHA384", L"SHA512"};
            ecdsaCap.defaultKeySize = 256;
            ecdsaCap.supportsKeyGeneration = true;
            ecdsaCap.supportsKeyImport = true;
            ecdsaCap.supportsKeyExport = true;
            
            m_capabilities[NCRYPT_ECDSA_P256_ALGORITHM] = ecdsaCap;
            m_supportedAlgorithms.insert(NCRYPT_ECDSA_P256_ALGORITHM);
        }

        // Initialize ECDSA P-384 capabilities
        {
            AlgorithmCapability ecdsaCap;
            ecdsaCap.algorithmId = NCRYPT_ECDSA_P384_ALGORITHM;
            ecdsaCap.algorithmClass = NCRYPT_SIGNATURE_INTERFACE;
            ecdsaCap.supportedKeySizes = {384};
            ecdsaCap.supportedOperations = {NCRYPT_ALLOW_SIGNING_FLAG};
            ecdsaCap.supportedPadding = {L"None"};
            ecdsaCap.supportedHashAlgorithms = {L"SHA256", L"SHA384", L"SHA512"};
            ecdsaCap.defaultKeySize = 384;
            ecdsaCap.supportsKeyGeneration = true;
            ecdsaCap.supportsKeyImport = true;
            ecdsaCap.supportsKeyExport = true;
            
            m_capabilities[NCRYPT_ECDSA_P384_ALGORITHM] = ecdsaCap;
            m_supportedAlgorithms.insert(NCRYPT_ECDSA_P384_ALGORITHM);
        }

        // Initialize ECDSA P-521 capabilities
        {
            AlgorithmCapability ecdsaCap;
            ecdsaCap.algorithmId = NCRYPT_ECDSA_P521_ALGORITHM;
            ecdsaCap.algorithmClass = NCRYPT_SIGNATURE_INTERFACE;
            ecdsaCap.supportedKeySizes = {521};
            ecdsaCap.supportedOperations = {NCRYPT_ALLOW_SIGNING_FLAG};
            ecdsaCap.supportedPadding = {L"None"};
            ecdsaCap.supportedHashAlgorithms = {L"SHA256", L"SHA384", L"SHA512"};
            ecdsaCap.defaultKeySize = 521;
            ecdsaCap.supportsKeyGeneration = true;
            ecdsaCap.supportsKeyImport = true;
            ecdsaCap.supportsKeyExport = true;
            
            m_capabilities[NCRYPT_ECDSA_P521_ALGORITHM] = ecdsaCap;
            m_supportedAlgorithms.insert(NCRYPT_ECDSA_P521_ALGORITHM);
        }

        // Initialize algorithm mappings
        m_algorithmMap[NCRYPT_RSA_ALGORITHM] = "RSA";
        m_algorithmMap[NCRYPT_ECDSA_P256_ALGORITHM] = "ECDSA_P256";
        m_algorithmMap[NCRYPT_ECDSA_P384_ALGORITHM] = "ECDSA_P384";
        m_algorithmMap[NCRYPT_ECDSA_P521_ALGORITHM] = "ECDSA_P521";

        // Initialize hash algorithm mappings
        m_hashAlgorithmMap[L"SHA1"] = "SHA1";
        m_hashAlgorithmMap[L"SHA256"] = "SHA256";
        m_hashAlgorithmMap[L"SHA384"] = "SHA384";
        m_hashAlgorithmMap[L"SHA512"] = "SHA512";

        // Initialize padding mappings
        m_paddingMap[NCRYPT_PAD_PKCS1_FLAG] = "PKCS1";
        m_paddingMap[NCRYPT_PAD_PSS_FLAG] = "PSS";
        m_paddingMap[NCRYPT_PAD_OAEP_FLAG] = "OAEP";

        // Initialize default key sizes
        m_defaultKeySizes[NCRYPT_RSA_ALGORITHM] = 2048;
        m_defaultKeySizes[NCRYPT_ECDSA_P256_ALGORITHM] = 256;
        m_defaultKeySizes[NCRYPT_ECDSA_P384_ALGORITHM] = 384;
        m_defaultKeySizes[NCRYPT_ECDSA_P521_ALGORITHM] = 521;

        // Initialize valid key sizes
        m_validKeySizes[NCRYPT_RSA_ALGORITHM] = {1024, 2048, 3072, 4096};
        m_validKeySizes[NCRYPT_ECDSA_P256_ALGORITHM] = {256};
        m_validKeySizes[NCRYPT_ECDSA_P384_ALGORITHM] = {384};
        m_validKeySizes[NCRYPT_ECDSA_P521_ALGORITHM] = {521};

        LogInfo(L"Algorithm capabilities initialized for %zu algorithms", m_capabilities.size());
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        LogError(L"Exception initializing algorithm capabilities: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

// Additional helper method implementations would continue here...

std::string AlgorithmProvider::ConvertAlgorithmToBackend(const std::wstring& cngAlgorithm)
{
    auto iter = m_algorithmMap.find(cngAlgorithm);
    if (iter != m_algorithmMap.end())
    {
        return iter->second;
    }
    
    // Fallback conversion
    if (cngAlgorithm == NCRYPT_RSA_ALGORITHM)
        return "RSA";
    else if (cngAlgorithm == NCRYPT_ECDSA_P256_ALGORITHM)
        return "ECDSA_P256";
    else if (cngAlgorithm == NCRYPT_ECDSA_P384_ALGORITHM)
        return "ECDSA_P384";
    else if (cngAlgorithm == NCRYPT_ECDSA_P521_ALGORITHM)
        return "ECDSA_P521";
    
    return "UNKNOWN";
}

std::string AlgorithmProvider::ConvertHashAlgorithmToBackend(const std::wstring& hashAlgorithm)
{
    auto iter = m_hashAlgorithmMap.find(hashAlgorithm);
    if (iter != m_hashAlgorithmMap.end())
    {
        return iter->second;
    }
    
    return "SHA256"; // Safe default
}

DWORD AlgorithmProvider::CalculateSignatureSize(
    const std::wstring& algorithm,
    DWORD keySize,
    const RsaPaddingInfo* paddingInfo)
{
    if (algorithm.find(L"RSA") != std::wstring::npos)
    {
        // RSA signature size is always key size in bytes
        return keySize / 8;
    }
    else if (algorithm.find(L"ECDSA") != std::wstring::npos)
    {
        // ECDSA signature size is approximately 2 * key size in bytes
        // For DER encoding, add some overhead
        return ((keySize / 8) * 2) + 16;
    }
    
    return 0;
}

DWORD AlgorithmProvider::CalculateEncryptionSize(
    const std::wstring& algorithm,
    DWORD keySize,
    DWORD inputSize,
    const RsaPaddingInfo* paddingInfo)
{
    if (algorithm.find(L"RSA") != std::wstring::npos)
    {
        // RSA encryption output is always key size in bytes
        return keySize / 8;
    }
    
    return 0; // ECC doesn't support encryption
}

// Additional method implementations would continue...

} // namespace ksp
} // namespace supacrypt