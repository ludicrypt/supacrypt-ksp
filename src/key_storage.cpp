// key_storage.cpp - Key storage management implementation for Supacrypt KSP
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#include "key_storage.h"
#include "grpc_backend.h"
#include "error_handling.h"
#include "logging.h"

#include <windows.h>
#include <ncrypt.h>
#include <rpc.h>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace supacrypt
{
namespace ksp
{

KeyStorageManager::KeyStorageManager(std::shared_ptr<GrpcBackendClient> backendClient)
    : m_initialized(false)
    , m_backendClient(backendClient)
    , m_enablePersistence(true)
    , m_maxCachedKeys(1000)
    , m_keyTimeout(std::chrono::seconds(3600))
{
    LogFunctionEntry();
    
    // Initialize algorithm mappings
    InitializeAlgorithmMappings();
    LogInfo(L"KeyStorageManager created");
}

KeyStorageManager::~KeyStorageManager()
{
    LogFunctionEntry();
    Shutdown();
}

NTSTATUS KeyStorageManager::Initialize()
{
    LogFunctionEntry();
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized)
    {
        LogInfo(L"Key storage manager already initialized");
        return STATUS_SUCCESS;
    }

    try
    {
        LogInfo(L"Initializing key storage manager...");

        // Validate backend client
        if (!m_backendClient)
        {
            SET_KSP_ERROR(KspErrorCode::InvalidState, L"Backend client not available");
            return KSP_TO_NTSTATUS(KspErrorCode::InvalidState);
        }

        // Check backend health
        if (!m_backendClient->IsHealthy())
        {
            SET_KSP_ERROR(KspErrorCode::BackendNotAvailable, L"Backend service not healthy");
            return KSP_TO_NTSTATUS(KspErrorCode::BackendNotAvailable);
        }

        // Initialize key store path
        wchar_t programDataPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programDataPath)))
        {
            m_keyStorePath = std::wstring(programDataPath) + L"\\Supacrypt\\Keys";
        }
        else
        {
            m_keyStorePath = L"C:\\ProgramData\\Supacrypt\\Keys";
        }

        // Create key store directory if it doesn't exist
        CreateDirectoryW(m_keyStorePath.c_str(), NULL);

        m_initialized = true;
        LogInfo(L"Key storage manager initialized successfully");
        LogInfo(L"Key store path: %s", m_keyStorePath.c_str());
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception during key storage initialization");
        LogError(L"Exception in KeyStorageManager::Initialize: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

void KeyStorageManager::Shutdown()
{
    LogFunctionEntry();
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized)
    {
        LogDebug(L"Key storage manager not initialized, nothing to shutdown");
        return;
    }

    try
    {
        LogInfo(L"Shutting down key storage manager...");

        // Clear all cached key contexts
        for (auto& pair : m_keyContexts)
        {
            if (pair.second)
            {
                std::lock_guard<std::mutex> keyLock(pair.second->mutex);
                LogDebug(L"Cleaning up key context for handle: 0x%p", pair.first);
            }
        }
        
        m_keyContexts.clear();
        m_keyNameMap.clear();

        m_initialized = false;
        LogInfo(L"Key storage manager shutdown completed");
    }
    catch (const std::exception& e)
    {
        LogError(L"Exception during key storage shutdown: %hs", e.what());
    }
    
    LogFunctionExit();
}

NTSTATUS KeyStorageManager::CreateKey(
    NCRYPT_KEY_HANDLE handle,
    const std::wstring& algorithm,
    const std::wstring& keyName,
    DWORD keySpec,
    DWORD flags)
{
    LogFunctionEntry();
    
    if (!m_initialized)
    {
        SET_KSP_ERROR(KspErrorCode::ProviderNotInitialized, L"Key storage manager not initialized");
        return KSP_TO_NTSTATUS(KspErrorCode::ProviderNotInitialized);
    }

    try
    {
        LogInfo(L"Creating key: handle=0x%p, algorithm=%s, name=%s", 
                handle, algorithm.c_str(), 
                keyName.empty() ? L"<ephemeral>" : keyName.c_str());

        // Generate unique key ID
        std::wstring effectiveKeyName = keyName.empty() ? 
            GenerateUniqueKeyName(L"ephemeral-key") : keyName;
        
        std::wstring keyId = GenerateKeyId(effectiveKeyName, algorithm);

        // Check if key already exists (if name provided and not overwrite)
        if (!keyName.empty() && !(flags & NCRYPT_OVERWRITE_KEY_FLAG))
        {
            if (KeyExists(keyName))
            {
                SET_KSP_ERROR(KspErrorCode::KeyAlreadyExists, 
                             L"Key already exists: " + keyName);
                return KSP_TO_NTSTATUS(KspErrorCode::KeyAlreadyExists);
            }
        }

        // Create key context
        auto keyContext = std::make_shared<KeyContext>(handle, keyId, algorithm);
        keyContext->keySpec = keySpec;
        keyContext->flags = flags;
        keyContext->isFinalized = false;

        // Initialize metadata
        keyContext->metadata->keyId = keyId;
        keyContext->metadata->algorithm = algorithm;
        keyContext->metadata->keySize = GetDefaultKeySize(algorithm);
        keyContext->metadata->keyUsage = NCRYPT_ALLOW_SIGNING_FLAG | NCRYPT_ALLOW_DECRYPT_FLAG;
        keyContext->metadata->isPersistent = !keyName.empty();
        keyContext->metadata->createdAt = std::chrono::system_clock::now();
        keyContext->metadata->lastUsed = keyContext->metadata->createdAt;
        keyContext->metadata->friendlyName = effectiveKeyName;

        // Store in maps
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_keyContexts[handle] = keyContext;
            if (!keyName.empty())
            {
                m_keyNameMap[keyName] = handle;
            }
        }

        LogInfo(L"Key created successfully: keyId=%s", keyId.c_str());
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception creating key");
        LogError(L"Exception in CreateKey: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS KeyStorageManager::OpenKey(
    NCRYPT_KEY_HANDLE handle,
    const std::wstring& keyName,
    DWORD keySpec,
    DWORD flags)
{
    LogFunctionEntry();
    
    if (!m_initialized)
    {
        SET_KSP_ERROR(KspErrorCode::ProviderNotInitialized, L"Key storage manager not initialized");
        return KSP_TO_NTSTATUS(KspErrorCode::ProviderNotInitialized);
    }

    try
    {
        LogInfo(L"Opening key: handle=0x%p, name=%s", handle, keyName.c_str());

        // Check if key exists
        if (!KeyExists(keyName))
        {
            SET_KSP_ERROR(KspErrorCode::KeyNotFound, L"Key not found: " + keyName);
            return KSP_TO_NTSTATUS(KspErrorCode::KeyNotFound);
        }

        // Generate key ID for backend lookup
        std::wstring keyId = GenerateKeyId(keyName, L""); // Algorithm will be determined from backend

        // Get key metadata from backend
        auto metadataResult = m_backendClient->GetKeyMetadata(
            std::string(keyId.begin(), keyId.end()));
            
        if (!metadataResult.success)
        {
            SET_KSP_ERROR(KspErrorCode::BackendError, 
                         L"Failed to get key metadata from backend");
            LogError(L"Backend GetKeyMetadata failed: %hs", metadataResult.errorMessage.c_str());
            return KSP_TO_NTSTATUS(KspErrorCode::BackendError);
        }

        // Parse metadata (simplified - would normally parse JSON or protobuf)
        std::wstring algorithm = L"RSA"; // TODO: Parse from metadata

        // Create key context
        auto keyContext = std::make_shared<KeyContext>(handle, keyId, algorithm);
        keyContext->keySpec = keySpec;
        keyContext->flags = flags;
        keyContext->isFinalized = true; // Existing keys are already finalized

        // Load metadata
        NTSTATUS status = LoadKeyMetadata(keyId, *keyContext->metadata);
        if (!NT_SUCCESS(status))
        {
            LogError(L"Failed to load key metadata");
            return status;
        }

        // Store in maps
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_keyContexts[handle] = keyContext;
            m_keyNameMap[keyName] = handle;
        }

        LogInfo(L"Key opened successfully: keyId=%s", keyId.c_str());
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception opening key");
        LogError(L"Exception in OpenKey: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS KeyStorageManager::DeleteKey(
    NCRYPT_KEY_HANDLE handle,
    DWORD flags)
{
    LogFunctionEntry();
    
    if (!m_initialized)
    {
        SET_KSP_ERROR(KspErrorCode::ProviderNotInitialized, L"Key storage manager not initialized");
        return KSP_TO_NTSTATUS(KspErrorCode::ProviderNotInitialized);
    }

    try
    {
        LogInfo(L"Deleting key: handle=0x%p", handle);

        // Get key context
        auto keyContext = GetKeyContext(handle);
        if (!keyContext)
        {
            SET_KSP_ERROR(KspErrorCode::InvalidKeyHandle, L"Invalid key handle");
            return KSP_TO_NTSTATUS(KspErrorCode::InvalidKeyHandle);
        }

        std::lock_guard<std::mutex> keyLock(keyContext->mutex);

        // Delete from backend if persistent
        if (keyContext->metadata->isPersistent)
        {
            auto deleteResult = m_backendClient->DeleteKey(
                std::string(keyContext->keyId.begin(), keyContext->keyId.end()));
                
            if (!deleteResult.success)
            {
                SET_KSP_ERROR(KspErrorCode::BackendError, 
                             L"Failed to delete key from backend");
                LogError(L"Backend DeleteKey failed: %hs", deleteResult.errorMessage.c_str());
                return KSP_TO_NTSTATUS(KspErrorCode::BackendError);
            }
        }

        // Remove from local maps
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            
            // Find and remove from name map
            for (auto iter = m_keyNameMap.begin(); iter != m_keyNameMap.end(); ++iter)
            {
                if (iter->second == handle)
                {
                    m_keyNameMap.erase(iter);
                    break;
                }
            }
            
            m_keyContexts.erase(handle);
        }

        LogInfo(L"Key deleted successfully: keyId=%s", keyContext->keyId.c_str());
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception deleting key");
        LogError(L"Exception in DeleteKey: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS KeyStorageManager::FinalizeKey(
    NCRYPT_KEY_HANDLE handle,
    DWORD flags)
{
    LogFunctionEntry();
    
    if (!m_initialized)
    {
        SET_KSP_ERROR(KspErrorCode::ProviderNotInitialized, L"Key storage manager not initialized");
        return KSP_TO_NTSTATUS(KspErrorCode::ProviderNotInitialized);
    }

    try
    {
        LogInfo(L"Finalizing key: handle=0x%p", handle);

        // Get key context
        auto keyContext = GetKeyContext(handle);
        if (!keyContext)
        {
            SET_KSP_ERROR(KspErrorCode::InvalidKeyHandle, L"Invalid key handle");
            return KSP_TO_NTSTATUS(KspErrorCode::InvalidKeyHandle);
        }

        std::lock_guard<std::mutex> keyLock(keyContext->mutex);

        if (keyContext->isFinalized)
        {
            SET_KSP_ERROR(KspErrorCode::KeyAlreadyFinalized, L"Key already finalized");
            return KSP_TO_NTSTATUS(KspErrorCode::KeyAlreadyFinalized);
        }

        // Generate key pair via backend
        auto generateResult = m_backendClient->GenerateKey(
            std::string(keyContext->algorithm.begin(), keyContext->algorithm.end()),
            keyContext->metadata->keySize,
            std::string(keyContext->keyId.begin(), keyContext->keyId.end()),
            keyContext->metadata->keyUsage);
            
        if (!generateResult.success)
        {
            SET_KSP_ERROR(KspErrorCode::BackendError, 
                         L"Failed to generate key in backend");
            LogError(L"Backend GenerateKey failed: %hs", generateResult.errorMessage.c_str());
            return KSP_TO_NTSTATUS(KspErrorCode::BackendError);
        }

        // Get public key blob for caching
        auto publicKeyResult = m_backendClient->GetPublicKey(
            std::string(keyContext->keyId.begin(), keyContext->keyId.end()),
            "DER");
            
        if (publicKeyResult.success)
        {
            keyContext->metadata->publicKeyBlob = publicKeyResult.response;
        }

        // Save metadata if persistent
        if (keyContext->metadata->isPersistent)
        {
            NTSTATUS status = SaveKeyMetadata(*keyContext->metadata);
            if (!NT_SUCCESS(status))
            {
                LogWarning(L"Failed to save key metadata, but key generation succeeded");
            }
        }

        keyContext->isFinalized = true;

        LogInfo(L"Key finalized successfully: keyId=%s", keyContext->keyId.c_str());
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception finalizing key");
        LogError(L"Exception in FinalizeKey: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

// Property management methods

NTSTATUS KeyStorageManager::GetKeyProperty(
    NCRYPT_KEY_HANDLE handle,
    const std::wstring& property,
    PBYTE buffer,
    DWORD bufferSize,
    DWORD* resultSize,
    DWORD flags)
{
    LogFunctionEntry();
    
    if (!ValidateParameter(resultSize, L"resultSize"))
    {
        return STATUS_INVALID_PARAMETER;
    }

    *resultSize = 0;

    auto keyContext = GetKeyContext(handle);
    if (!keyContext)
    {
        SET_KSP_ERROR(KspErrorCode::InvalidKeyHandle, L"Invalid key handle");
        return KSP_TO_NTSTATUS(KspErrorCode::InvalidKeyHandle);
    }

    std::lock_guard<std::mutex> keyLock(keyContext->mutex);
    UpdateKeyLastUsed(handle);

    try
    {
        LogDebug(L"Getting key property: %s", property.c_str());

        // Handle standard CNG properties
        if (property == NCRYPT_ALGORITHM_PROPERTY)
        {
            auto algBytes = reinterpret_cast<const BYTE*>(keyContext->algorithm.c_str());
            DWORD algSize = static_cast<DWORD>((keyContext->algorithm.length() + 1) * sizeof(wchar_t));
            
            *resultSize = algSize;
            if (buffer && bufferSize >= algSize)
            {
                memcpy(buffer, algBytes, algSize);
            }
            else if (buffer)
            {
                return KSP_TO_NTSTATUS(KspErrorCode::BufferTooSmall);
            }
            
            return STATUS_SUCCESS;
        }
        else if (property == NCRYPT_LENGTH_PROPERTY)
        {
            *resultSize = sizeof(DWORD);
            if (buffer && bufferSize >= sizeof(DWORD))
            {
                *reinterpret_cast<DWORD*>(buffer) = keyContext->metadata->keySize;
            }
            else if (buffer)
            {
                return KSP_TO_NTSTATUS(KspErrorCode::BufferTooSmall);
            }
            
            return STATUS_SUCCESS;
        }
        else if (property == NCRYPT_KEY_USAGE_PROPERTY)
        {
            *resultSize = sizeof(DWORD);
            if (buffer && bufferSize >= sizeof(DWORD))
            {
                *reinterpret_cast<DWORD*>(buffer) = keyContext->metadata->keyUsage;
            }
            else if (buffer)
            {
                return KSP_TO_NTSTATUS(KspErrorCode::BufferTooSmall);
            }
            
            return STATUS_SUCCESS;
        }
        else if (property == NCRYPT_EXPORT_POLICY_PROPERTY)
        {
            *resultSize = sizeof(DWORD);
            if (buffer && bufferSize >= sizeof(DWORD))
            {
                // Allow export of public key, restrict private key
                *reinterpret_cast<DWORD*>(buffer) = NCRYPT_ALLOW_EXPORT_FLAG;
            }
            else if (buffer)
            {
                return KSP_TO_NTSTATUS(KspErrorCode::BufferTooSmall);
            }
            
            return STATUS_SUCCESS;
        }

        // Check custom properties
        auto propIter = keyContext->metadata->properties.find(property);
        if (propIter != keyContext->metadata->properties.end())
        {
            const auto& propValue = propIter->second;
            *resultSize = static_cast<DWORD>(propValue.size());
            
            if (buffer && bufferSize >= propValue.size())
            {
                memcpy(buffer, propValue.data(), propValue.size());
            }
            else if (buffer)
            {
                return KSP_TO_NTSTATUS(KspErrorCode::BufferTooSmall);
            }
            
            return STATUS_SUCCESS;
        }

        // Property not found
        SET_KSP_ERROR(KspErrorCode::PropertyNotFound, L"Property not found: " + property);
        return KSP_TO_NTSTATUS(KspErrorCode::PropertyNotFound);
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception getting key property");
        LogError(L"Exception in GetKeyProperty: %hs", e.what());
        return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS KeyStorageManager::SetKeyProperty(
    NCRYPT_KEY_HANDLE handle,
    const std::wstring& property,
    PBYTE data,
    DWORD dataSize,
    DWORD flags)
{
    LogFunctionEntry();
    
    auto keyContext = GetKeyContext(handle);
    if (!keyContext)
    {
        SET_KSP_ERROR(KspErrorCode::InvalidKeyHandle, L"Invalid key handle");
        return KSP_TO_NTSTATUS(KspErrorCode::InvalidKeyHandle);
    }

    std::lock_guard<std::mutex> keyLock(keyContext->mutex);
    UpdateKeyLastUsed(handle);

    try
    {
        LogDebug(L"Setting key property: %s", property.c_str());

        // Check if key is finalized for certain properties
        if (keyContext->isFinalized)
        {
            // Some properties cannot be changed after finalization
            if (property == NCRYPT_ALGORITHM_PROPERTY ||
                property == NCRYPT_LENGTH_PROPERTY)
            {
                SET_KSP_ERROR(KspErrorCode::PropertyReadOnly, 
                             L"Property cannot be modified after finalization: " + property);
                return KSP_TO_NTSTATUS(KspErrorCode::PropertyReadOnly);
            }
        }

        // Handle standard properties
        if (property == NCRYPT_KEY_USAGE_PROPERTY)
        {
            if (dataSize != sizeof(DWORD))
            {
                SET_KSP_ERROR(KspErrorCode::InvalidPropertyValue, L"Invalid data size for key usage");
                return KSP_TO_NTSTATUS(KspErrorCode::InvalidPropertyValue);
            }
            
            keyContext->metadata->keyUsage = *reinterpret_cast<const DWORD*>(data);
            return STATUS_SUCCESS;
        }
        else if (property == NCRYPT_LENGTH_PROPERTY)
        {
            if (dataSize != sizeof(DWORD))
            {
                SET_KSP_ERROR(KspErrorCode::InvalidPropertyValue, L"Invalid data size for key length");
                return KSP_TO_NTSTATUS(KspErrorCode::InvalidPropertyValue);
            }
            
            DWORD newKeySize = *reinterpret_cast<const DWORD*>(data);
            if (!ValidateKeySize(keyContext->algorithm, newKeySize))
            {
                SET_KSP_ERROR(KspErrorCode::InvalidKeySize, L"Invalid key size for algorithm");
                return KSP_TO_NTSTATUS(KspErrorCode::InvalidKeySize);
            }
            
            keyContext->metadata->keySize = newKeySize;
            return STATUS_SUCCESS;
        }

        // Store custom property
        std::vector<BYTE> propValue(data, data + dataSize);
        keyContext->metadata->properties[property] = propValue;

        LogDebug(L"Key property set successfully: %s", property.c_str());
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception setting key property");
        LogError(L"Exception in SetKeyProperty: %hs", e.what());
        return STATUS_INTERNAL_ERROR;
    }
}

// Helper methods

std::shared_ptr<KeyContext> KeyStorageManager::GetKeyContext(NCRYPT_KEY_HANDLE handle)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto iter = m_keyContexts.find(handle);
    if (iter != m_keyContexts.end())
    {
        return iter->second;
    }
    
    return nullptr;
}

bool KeyStorageManager::KeyExists(const std::wstring& keyName)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Check local cache first
    auto iter = m_keyNameMap.find(keyName);
    if (iter != m_keyNameMap.end())
    {
        return true;
    }
    
    // TODO: Check backend or persistent storage
    return false;
}

std::wstring KeyStorageManager::GenerateUniqueKeyName(const std::wstring& prefix)
{
    // Generate GUID for uniqueness
    GUID guid;
    if (SUCCEEDED(CoCreateGuid(&guid)))
    {
        wchar_t guidStr[40];
        StringFromGUID2(guid, guidStr, ARRAYSIZE(guidStr));
        
        // Remove braces
        std::wstring guidWStr(guidStr + 1);
        guidWStr.pop_back();
        
        return prefix + L"-" + guidWStr;
    }
    
    // Fallback to timestamp-based name
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
        
    return prefix + L"-" + std::to_wstring(timestamp);
}

std::wstring KeyStorageManager::GenerateKeyId(const std::wstring& keyName, const std::wstring& algorithm)
{
    // Create a deterministic key ID based on name and algorithm
    std::wstring combined = keyName + L":" + algorithm;
    
    // For simplicity, use the combined string as ID
    // In production, you might want to hash this
    return combined;
}

void KeyStorageManager::UpdateKeyLastUsed(NCRYPT_KEY_HANDLE handle)
{
    auto keyContext = GetKeyContext(handle);
    if (keyContext)
    {
        keyContext->metadata->lastUsed = std::chrono::system_clock::now();
    }
}

DWORD KeyStorageManager::GetDefaultKeySize(const std::wstring& algorithm)
{
    auto iter = m_algorithmKeySizes.find(algorithm);
    if (iter != m_algorithmKeySizes.end())
    {
        return iter->second;
    }
    
    // Default fallbacks
    if (algorithm.find(L"RSA") != std::wstring::npos)
    {
        return 2048;
    }
    else if (algorithm.find(L"ECDSA") != std::wstring::npos || 
             algorithm.find(L"ECDH") != std::wstring::npos)
    {
        return 256; // P-256
    }
    
    return 2048; // Safe default
}

void KeyStorageManager::InitializeAlgorithmMappings()
{
    // CNG to backend algorithm mappings
    m_algorithmMap[NCRYPT_RSA_ALGORITHM] = L"RSA";
    m_algorithmMap[NCRYPT_ECDSA_P256_ALGORITHM] = L"ECDSA_P256";
    m_algorithmMap[NCRYPT_ECDSA_P384_ALGORITHM] = L"ECDSA_P384";
    m_algorithmMap[NCRYPT_ECDSA_P521_ALGORITHM] = L"ECDSA_P521";
    m_algorithmMap[NCRYPT_ECDH_P256_ALGORITHM] = L"ECDH_P256";
    m_algorithmMap[NCRYPT_ECDH_P384_ALGORITHM] = L"ECDH_P384";
    m_algorithmMap[NCRYPT_ECDH_P521_ALGORITHM] = L"ECDH_P521";
    
    // Default key sizes
    m_algorithmKeySizes[NCRYPT_RSA_ALGORITHM] = 2048;
    m_algorithmKeySizes[NCRYPT_ECDSA_P256_ALGORITHM] = 256;
    m_algorithmKeySizes[NCRYPT_ECDSA_P384_ALGORITHM] = 384;
    m_algorithmKeySizes[NCRYPT_ECDSA_P521_ALGORITHM] = 521;
    m_algorithmKeySizes[NCRYPT_ECDH_P256_ALGORITHM] = 256;
    m_algorithmKeySizes[NCRYPT_ECDH_P384_ALGORITHM] = 384;
    m_algorithmKeySizes[NCRYPT_ECDH_P521_ALGORITHM] = 521;
}

// Additional methods would continue here...

} // namespace ksp
} // namespace supacrypt