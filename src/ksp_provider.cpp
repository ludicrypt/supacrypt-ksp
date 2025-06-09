// ksp_provider.cpp - Main KSP provider implementation for Supacrypt
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#include "ksp_provider.h"
#include "key_storage.h"
#include "algorithm_provider.h"
#include "grpc_backend.h"
#include "error_handling.h"
#include "logging.h"

#include <windows.h>
#include <ncrypt.h>
#include <memory>
#include <string>
#include <mutex>
#include <atomic>

namespace supacrypt
{
namespace ksp
{

// Static members
std::unique_ptr<WindowsKspProvider> WindowsKspProvider::s_instance;
std::once_flag WindowsKspProvider::s_instanceFlag;

// NCrypt function table for Key Storage Interface
static NCRYPT_KEY_STORAGE_INTERFACE_FN_TABLE g_keyStorageFunctionTable = {
    NCRYPT_KEY_STORAGE_INTERFACE_VERSION,
    nullptr,  // OpenProvider - filled in initialization
    nullptr,  // OpenKey
    nullptr,  // CreatePersistedKey
    nullptr,  // GetProviderProperty
    nullptr,  // GetKeyProperty
    nullptr,  // SetProviderProperty
    nullptr,  // SetKeyProperty
    nullptr,  // FinalizeKey
    nullptr,  // DeleteKey
    nullptr,  // FreeKey
    nullptr,  // FreeBuffer
    nullptr,  // Encrypt
    nullptr,  // Decrypt
    nullptr,  // IsAlgSupported
    nullptr,  // EnumAlgorithms
    nullptr,  // EnumKeys
    nullptr,  // ImportKey
    nullptr,  // ExportKey
    nullptr,  // SignHash
    nullptr,  // VerifySignature
    nullptr,  // PromptUser
    nullptr,  // NotifyChangeKey
    nullptr,  // SecretAgreement
    nullptr,  // DeriveKey
    nullptr   // FreeSecret
};

WindowsKspProvider::WindowsKspProvider()
    : m_initialized(false)
    , m_nextHandle(1000)
    , m_providerName(L"Supacrypt Key Storage Provider")
    , m_backendEndpoint(L"localhost:50051")
{
    LogFunctionEntry();
}

WindowsKspProvider::~WindowsKspProvider()
{
    LogFunctionEntry();
    Shutdown();
}

WindowsKspProvider& WindowsKspProvider::GetInstance()
{
    std::call_once(s_instanceFlag, []() {
        s_instance = std::unique_ptr<WindowsKspProvider>(new WindowsKspProvider());
    });
    return *s_instance;
}

NTSTATUS WindowsKspProvider::Initialize()
{
    LogFunctionEntry();
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized)
    {
        LogInfo(L"KSP provider already initialized");
        return STATUS_SUCCESS;
    }

    try
    {
        LogInfo(L"Initializing Supacrypt KSP provider...");

        // Initialize backend connection
        NTSTATUS status = InitializeBackend();
        if (!NT_SUCCESS(status))
        {
            SET_KSP_ERROR(KspErrorCode::BackendConnectionFailed, L"Failed to initialize backend connection");
            LogError(L"Backend initialization failed with status: 0x%08lX", status);
            return status;
        }

        // Initialize key storage manager
        m_keyStorage = std::make_unique<KeyStorageManager>(m_backendClient);
        status = m_keyStorage->Initialize();
        if (!NT_SUCCESS(status))
        {
            SET_KSP_ERROR(KspErrorCode::InternalError, L"Failed to initialize key storage manager");
            LogError(L"Key storage initialization failed with status: 0x%08lX", status);
            return status;
        }

        // Initialize algorithm providers
        status = InitializeAlgorithms();
        if (!NT_SUCCESS(status))
        {
            SET_KSP_ERROR(KspErrorCode::InternalError, L"Failed to initialize algorithm providers");
            LogError(L"Algorithm initialization failed with status: 0x%08lX", status);
            return status;
        }

        // Initialize error handler
        m_errorHandler = std::make_unique<ErrorHandler>();

        m_initialized = true;
        LogInfo(L"Supacrypt KSP provider initialized successfully");
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception during initialization");
        LogError(L"Exception during KSP initialization: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

void WindowsKspProvider::Shutdown()
{
    LogFunctionEntry();
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized)
    {
        LogDebug(L"KSP provider not initialized, nothing to shutdown");
        return;
    }

    try
    {
        LogInfo(L"Shutting down Supacrypt KSP provider...");

        // Close all open handles
        m_keyHandles.clear();
        m_providerHandles.clear();

        // Shutdown components in reverse order
        if (m_algorithms)
        {
            m_algorithms->Shutdown();
            m_algorithms.reset();
        }

        if (m_keyStorage)
        {
            m_keyStorage->Shutdown();
            m_keyStorage.reset();
        }

        if (m_backendClient)
        {
            m_backendClient->Shutdown();
            m_backendClient.reset();
        }

        m_errorHandler.reset();

        m_initialized = false;
        LogInfo(L"Supacrypt KSP provider shutdown completed");
    }
    catch (const std::exception& e)
    {
        LogError(L"Exception during KSP shutdown: %hs", e.what());
    }
    
    LogFunctionExit();
}

NTSTATUS WindowsKspProvider::GetInterface(
    LPCWSTR pszInterface,
    NCRYPT_INTERFACE_FN_TABLE** ppFunctionTable,
    DWORD dwFlags)
{
    LogFunctionEntry();
    
    if (!ValidateParameter(pszInterface, L"pszInterface") ||
        !ValidateParameter(ppFunctionTable, L"ppFunctionTable"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (!ValidateFlags(dwFlags, 0, L"dwFlags"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    *ppFunctionTable = nullptr;

    // Check for Key Storage Interface
    if (wcscmp(pszInterface, NCRYPT_KEY_STORAGE_INTERFACE) == 0)
    {
        // Initialize function table if not already done
        if (g_keyStorageFunctionTable.OpenProvider == nullptr)
        {
            g_keyStorageFunctionTable.OpenProvider = 
                reinterpret_cast<PFN_NCRYPT_OPEN_PROVIDER>(::OpenProvider);
            g_keyStorageFunctionTable.OpenKey = 
                reinterpret_cast<PFN_NCRYPT_OPEN_KEY>(::OpenKey);
            g_keyStorageFunctionTable.CreatePersistedKey = 
                reinterpret_cast<PFN_NCRYPT_CREATE_PERSISTED_KEY>(::CreateKey);
            g_keyStorageFunctionTable.FinalizeKey = 
                reinterpret_cast<PFN_NCRYPT_FINALIZE_KEY>(::FinalizeKey);
            g_keyStorageFunctionTable.DeleteKey = 
                reinterpret_cast<PFN_NCRYPT_DELETE_KEY>(::DeleteKey);
            g_keyStorageFunctionTable.SignHash = 
                reinterpret_cast<PFN_NCRYPT_SIGN_HASH>(::SignHash);
            g_keyStorageFunctionTable.VerifySignature = 
                reinterpret_cast<PFN_NCRYPT_VERIFY_SIGNATURE>(::VerifySignature);
            // ... other function pointers would be initialized here
        }

        *ppFunctionTable = reinterpret_cast<NCRYPT_INTERFACE_FN_TABLE*>(&g_keyStorageFunctionTable);
        
        LogInfo(L"Provided Key Storage Interface function table");
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    // Interface not supported
    SET_KSP_ERROR(KspErrorCode::NotSupported, L"Requested interface not supported");
    LogWarning(L"Unsupported interface requested: %s", pszInterface);
    LogFunctionExitWithStatus(STATUS_NOT_SUPPORTED);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS WindowsKspProvider::OpenProvider(
    NCRYPT_PROV_HANDLE* phProvider,
    LPCWSTR pszProviderName,
    DWORD dwFlags)
{
    LogFunctionEntry();
    
    if (!ValidateParameter(phProvider, L"phProvider"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (!ValidateFlags(dwFlags, NCRYPT_SILENT_FLAG, L"dwFlags"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    *phProvider = 0;

    // Ensure provider is initialized
    if (!m_initialized)
    {
        NTSTATUS status = Initialize();
        if (!NT_SUCCESS(status))
        {
            LogFunctionExitWithStatus(status);
            return status;
        }
    }

    // Validate provider name (optional parameter)
    if (pszProviderName && wcscmp(pszProviderName, m_providerName.c_str()) != 0)
    {
        SET_KSP_ERROR(KspErrorCode::NotFound, L"Provider name does not match");
        LogWarning(L"Invalid provider name: %s", pszProviderName);
        LogFunctionExitWithStatus(STATUS_NOT_FOUND);
        return STATUS_NOT_FOUND;
    }

    try
    {
        // Generate new provider handle
        NCRYPT_PROV_HANDLE handle = GenerateHandle();
        
        // Add to tracking
        AddProviderHandle(handle);
        
        *phProvider = handle;
        
        LogInfo(L"Provider opened successfully, handle: 0x%p", handle);
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception opening provider");
        LogError(L"Exception in OpenProvider: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS WindowsKspProvider::CloseProvider(
    NCRYPT_PROV_HANDLE hProvider,
    DWORD dwFlags)
{
    LogFunctionEntry();
    
    if (!ValidateFlags(dwFlags, 0, L"dwFlags"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (!IsValidHandle(hProvider))
    {
        SET_KSP_ERROR(KspErrorCode::InvalidProviderHandle, L"Invalid provider handle");
        LogFunctionExitWithStatus(STATUS_INVALID_HANDLE);
        return STATUS_INVALID_HANDLE;
    }

    try
    {
        RemoveProviderHandle(hProvider);
        
        LogInfo(L"Provider closed successfully, handle: 0x%p", hProvider);
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception closing provider");
        LogError(L"Exception in CloseProvider: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS WindowsKspProvider::CreateKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE* phKey,
    LPCWSTR pszAlgId,
    LPCWSTR pszKeyName,
    DWORD dwLegacyKeySpec,
    DWORD dwFlags)
{
    LogFunctionEntry();
    
    if (!ValidateParameter(phKey, L"phKey") ||
        !ValidateParameter(pszAlgId, L"pszAlgId"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (!IsValidHandle(hProvider))
    {
        SET_KSP_ERROR(KspErrorCode::InvalidProviderHandle, L"Invalid provider handle");
        LogFunctionExitWithStatus(STATUS_INVALID_HANDLE);
        return STATUS_INVALID_HANDLE;
    }

    if (!ValidateFlags(dwFlags, 
        NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_SILENT_FLAG,
        L"dwFlags"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    *phKey = 0;

    try
    {
        // Generate unique key handle
        NCRYPT_KEY_HANDLE keyHandle = GenerateHandle();
        
        // Convert algorithm name
        std::wstring algorithm(pszAlgId);
        std::wstring keyName = pszKeyName ? std::wstring(pszKeyName) : L"";
        
        // Delegate to key storage manager
        NTSTATUS status = m_keyStorage->CreateKey(
            keyHandle,
            algorithm,
            keyName,
            dwLegacyKeySpec,
            dwFlags);
            
        if (!NT_SUCCESS(status))
        {
            LogError(L"Key storage CreateKey failed with status: 0x%08lX", status);
            LogFunctionExitWithStatus(status);
            return status;
        }

        // Add to handle tracking
        AddKeyHandle(keyHandle, keyName);
        
        *phKey = keyHandle;
        
        LogInfo(L"Key created successfully, handle: 0x%p, algorithm: %s", 
                keyHandle, pszAlgId);
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

NTSTATUS WindowsKspProvider::OpenKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE* phKey,
    LPCWSTR pszKeyName,
    DWORD dwLegacyKeySpec,
    DWORD dwFlags)
{
    LogFunctionEntry();
    
    if (!ValidateParameter(phKey, L"phKey") ||
        !ValidateParameter(pszKeyName, L"pszKeyName"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (!IsValidHandle(hProvider))
    {
        SET_KSP_ERROR(KspErrorCode::InvalidProviderHandle, L"Invalid provider handle");
        LogFunctionExitWithStatus(STATUS_INVALID_HANDLE);
        return STATUS_INVALID_HANDLE;
    }

    if (!ValidateFlags(dwFlags, 
        NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG,
        L"dwFlags"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    *phKey = 0;

    try
    {
        // Generate unique key handle
        NCRYPT_KEY_HANDLE keyHandle = GenerateHandle();
        
        std::wstring keyName(pszKeyName);
        
        // Delegate to key storage manager
        NTSTATUS status = m_keyStorage->OpenKey(
            keyHandle,
            keyName,
            dwLegacyKeySpec,
            dwFlags);
            
        if (!NT_SUCCESS(status))
        {
            LogError(L"Key storage OpenKey failed with status: 0x%08lX", status);
            LogFunctionExitWithStatus(status);
            return status;
        }

        // Add to handle tracking
        AddKeyHandle(keyHandle, keyName);
        
        *phKey = keyHandle;
        
        LogInfo(L"Key opened successfully, handle: 0x%p, name: %s", 
                keyHandle, pszKeyName);
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

// Implementing the remaining key methods...

NTSTATUS WindowsKspProvider::DeleteKey(
    NCRYPT_KEY_HANDLE hKey,
    DWORD dwFlags)
{
    LogFunctionEntry();
    
    if (!IsValidHandle(hKey))
    {
        SET_KSP_ERROR(KspErrorCode::InvalidKeyHandle, L"Invalid key handle");
        LogFunctionExitWithStatus(STATUS_INVALID_HANDLE);
        return STATUS_INVALID_HANDLE;
    }

    if (!ValidateFlags(dwFlags, NCRYPT_SILENT_FLAG, L"dwFlags"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    try
    {
        // Delegate to key storage manager
        NTSTATUS status = m_keyStorage->DeleteKey(hKey, dwFlags);
        
        if (NT_SUCCESS(status))
        {
            // Remove from handle tracking
            RemoveKeyHandle(hKey);
            LogInfo(L"Key deleted successfully, handle: 0x%p", hKey);
        }
        else
        {
            LogError(L"Key storage DeleteKey failed with status: 0x%08lX", status);
        }
        
        LogFunctionExitWithStatus(status);
        return status;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception deleting key");
        LogError(L"Exception in DeleteKey: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS WindowsKspProvider::FinalizeKey(
    NCRYPT_KEY_HANDLE hKey,
    DWORD dwFlags)
{
    LogFunctionEntry();
    
    if (!IsValidHandle(hKey))
    {
        SET_KSP_ERROR(KspErrorCode::InvalidKeyHandle, L"Invalid key handle");
        LogFunctionExitWithStatus(STATUS_INVALID_HANDLE);
        return STATUS_INVALID_HANDLE;
    }

    if (!ValidateFlags(dwFlags, NCRYPT_SILENT_FLAG, L"dwFlags"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    try
    {
        // Delegate to key storage manager
        NTSTATUS status = m_keyStorage->FinalizeKey(hKey, dwFlags);
        
        if (NT_SUCCESS(status))
        {
            LogInfo(L"Key finalized successfully, handle: 0x%p", hKey);
        }
        else
        {
            LogError(L"Key storage FinalizeKey failed with status: 0x%08lX", status);
        }
        
        LogFunctionExitWithStatus(status);
        return status;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception finalizing key");
        LogError(L"Exception in FinalizeKey: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

// Continue with cryptographic operations...

NTSTATUS WindowsKspProvider::SignHash(
    NCRYPT_KEY_HANDLE hKey,
    VOID* pPaddingInfo,
    PBYTE pbHashValue,
    DWORD cbHashValue,
    PBYTE pbSignature,
    DWORD cbSignature,
    DWORD* pcbResult,
    DWORD dwFlags)
{
    LogFunctionEntry();
    
    if (!IsValidHandle(hKey) ||
        !ValidateParameter(pbHashValue, L"pbHashValue") ||
        !ValidateParameter(pcbResult, L"pcbResult"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (!ValidateBuffer(pbHashValue, cbHashValue, 1, L"pbHashValue"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (!ValidateFlags(dwFlags, NCRYPT_SILENT_FLAG, L"dwFlags"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    try
    {
        // Delegate to algorithm provider
        NTSTATUS status = m_algorithms->SignHash(
            hKey,
            pPaddingInfo,
            pbHashValue,
            cbHashValue,
            pbSignature,
            cbSignature,
            pcbResult,
            dwFlags);
            
        if (NT_SUCCESS(status))
        {
            LogInfo(L"Hash signed successfully, handle: 0x%p, signature size: %lu", 
                    hKey, *pcbResult);
        }
        else
        {
            LogError(L"Algorithm SignHash failed with status: 0x%08lX", status);
        }
        
        LogFunctionExitWithStatus(status);
        return status;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::SigningFailed, L"Exception signing hash");
        LogError(L"Exception in SignHash: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS WindowsKspProvider::VerifySignature(
    NCRYPT_KEY_HANDLE hKey,
    VOID* pPaddingInfo,
    PBYTE pbHashValue,
    DWORD cbHashValue,
    PBYTE pbSignature,
    DWORD cbSignature,
    DWORD dwFlags)
{
    LogFunctionEntry();
    
    if (!IsValidHandle(hKey) ||
        !ValidateParameter(pbHashValue, L"pbHashValue") ||
        !ValidateParameter(pbSignature, L"pbSignature"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (!ValidateBuffer(pbHashValue, cbHashValue, 1, L"pbHashValue") ||
        !ValidateBuffer(pbSignature, cbSignature, 1, L"pbSignature"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (!ValidateFlags(dwFlags, NCRYPT_SILENT_FLAG, L"dwFlags"))
    {
        LogFunctionExitWithStatus(STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    try
    {
        // Delegate to algorithm provider
        NTSTATUS status = m_algorithms->VerifySignature(
            hKey,
            pPaddingInfo,
            pbHashValue,
            cbHashValue,
            pbSignature,
            cbSignature,
            dwFlags);
            
        if (NT_SUCCESS(status))
        {
            LogInfo(L"Signature verified successfully, handle: 0x%p", hKey);
        }
        else
        {
            LogWarning(L"Signature verification failed with status: 0x%08lX", status);
        }
        
        LogFunctionExitWithStatus(status);
        return status;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::VerificationFailed, L"Exception verifying signature");
        LogError(L"Exception in VerifySignature: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

// Private helper methods

NTSTATUS WindowsKspProvider::InitializeBackend()
{
    LogFunctionEntry();
    
    try
    {
        // Create backend configuration
        ConnectionConfig config;
        config.endpoint = "localhost:50051";  // TODO: Read from registry/config
        config.connectionTimeout = std::chrono::seconds(30);
        config.requestTimeout = std::chrono::seconds(60);
        config.maxConnections = 10;
        config.enableTls = true;
        
        // Create backend client
        m_backendClient = std::make_shared<GrpcBackendClient>(config);
        
        // Initialize connection
        NTSTATUS status = m_backendClient->Initialize();
        if (!NT_SUCCESS(status))
        {
            LogError(L"Failed to initialize gRPC backend client");
            return status;
        }
        
        LogInfo(L"Backend client initialized successfully");
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        LogError(L"Exception initializing backend: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS WindowsKspProvider::InitializeAlgorithms()
{
    LogFunctionEntry();
    
    try
    {
        // Create algorithm provider with dependencies
        m_algorithms = std::make_unique<AlgorithmProvider>(m_backendClient, m_keyStorage);
        
        // Initialize algorithm provider
        NTSTATUS status = m_algorithms->Initialize();
        if (!NT_SUCCESS(status))
        {
            LogError(L"Failed to initialize algorithm provider");
            return status;
        }
        
        LogInfo(L"Algorithm provider initialized successfully");
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        LogError(L"Exception initializing algorithms: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

bool WindowsKspProvider::IsValidHandle(NCRYPT_HANDLE handle) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Check provider handles
    auto provIter = m_providerHandles.find(static_cast<NCRYPT_PROV_HANDLE>(handle));
    if (provIter != m_providerHandles.end())
    {
        return true;
    }
    
    // Check key handles
    auto keyIter = m_keyHandles.find(static_cast<NCRYPT_KEY_HANDLE>(handle));
    if (keyIter != m_keyHandles.end())
    {
        return true;
    }
    
    return false;
}

NCRYPT_HANDLE WindowsKspProvider::GenerateHandle()
{
    return static_cast<NCRYPT_HANDLE>(m_nextHandle.fetch_add(1));
}

void WindowsKspProvider::AddProviderHandle(NCRYPT_PROV_HANDLE handle)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_providerHandles[handle] = true;
    LogDebug(L"Added provider handle: 0x%p", handle);
}

void WindowsKspProvider::RemoveProviderHandle(NCRYPT_PROV_HANDLE handle)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_providerHandles.erase(handle);
    LogDebug(L"Removed provider handle: 0x%p", handle);
}

void WindowsKspProvider::AddKeyHandle(NCRYPT_KEY_HANDLE handle, const std::wstring& keyName)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_keyHandles[handle] = keyName;
    LogDebug(L"Added key handle: 0x%p, name: %s", handle, keyName.c_str());
}

void WindowsKspProvider::RemoveKeyHandle(NCRYPT_KEY_HANDLE handle)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto iter = m_keyHandles.find(handle);
    if (iter != m_keyHandles.end())
    {
        LogDebug(L"Removed key handle: 0x%p, name: %s", handle, iter->second.c_str());
        m_keyHandles.erase(iter);
    }
}

} // namespace ksp
} // namespace supacrypt