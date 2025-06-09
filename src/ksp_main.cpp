// ksp_main.cpp - Main DLL entry point for Supacrypt KSP
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#include <windows.h>
#include <ncrypt.h>
#include <memory>
#include <string>
#include <mutex>
#include <atomic>

#include "ksp_provider.h"
#include "error_handling.h"
#include "logging.h"

namespace supacrypt
{
namespace ksp
{

// Global state
static std::atomic<bool> g_dllInitialized{false};
static std::atomic<DWORD> g_referenceCount{0};
static std::mutex g_initializationMutex;

// DLL instance handle
static HMODULE g_hModule = nullptr;

/// @brief DLL entry point
/// @param hModule Module handle
/// @param dwReason Reason for calling
/// @param lpReserved Reserved parameter
/// @return TRUE on success, FALSE on failure
BOOL WINAPI DllMain(
    _In_ HMODULE hModule,
    _In_ DWORD dwReason,
    _In_opt_ LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(lpReserved);

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        {
            // Disable thread library calls for performance
            DisableThreadLibraryCalls(hModule);
            
            g_hModule = hModule;
            
            // Initialize logging as early as possible
            if (!InitializeLogging())
            {
                return FALSE;
            }
            
            LogInfo(L"Supacrypt KSP DLL attached to process");
            
            // Early initialization check
            std::lock_guard<std::mutex> lock(g_initializationMutex);
            if (!g_dllInitialized.exchange(true))
            {
                // Initialize error handling
                if (!InitializeErrorHandling())
                {
                    LogError(L"Failed to initialize error handling");
                    g_dllInitialized = false;
                    return FALSE;
                }
                
                LogInfo(L"Supacrypt KSP DLL initialization completed");
            }
        }
        break;

    case DLL_PROCESS_DETACH:
        {
            LogInfo(L"Supacrypt KSP DLL detaching from process");
            
            // Ensure clean shutdown
            std::lock_guard<std::mutex> lock(g_initializationMutex);
            if (g_dllInitialized.exchange(false))
            {
                // Get provider instance and shutdown if needed
                auto& provider = WindowsKspProvider::GetInstance();
                provider.Shutdown();
                
                // Cleanup error handling
                ShutdownErrorHandling();
                
                LogInfo(L"Supacrypt KSP DLL shutdown completed");
            }
            
            // Shutdown logging last
            ShutdownLogging();
        }
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        // No per-thread initialization needed
        break;

    default:
        break;
    }

    return TRUE;
}

/// @brief Increment reference count
void IncrementReferenceCount()
{
    ++g_referenceCount;
    LogDebug(L"Reference count incremented to: %lu", g_referenceCount.load());
}

/// @brief Decrement reference count
void DecrementReferenceCount()
{
    DWORD count = --g_referenceCount;
    LogDebug(L"Reference count decremented to: %lu", count);
    
    if (count == 0)
    {
        LogInfo(L"Reference count reached zero - consider cleanup");
    }
}

/// @brief Get current reference count
DWORD GetReferenceCount()
{
    return g_referenceCount.load();
}

/// @brief Check if DLL is initialized
bool IsDllInitialized()
{
    return g_dllInitialized.load();
}

/// @brief Get DLL module handle
HMODULE GetModuleHandle()
{
    return g_hModule;
}

} // namespace ksp
} // namespace supacrypt

// Exported KSP interface functions
extern "C" {

/// @brief Get KSP interface
/// @param pszInterface Interface identifier
/// @param ppFunctionTable Pointer to function table
/// @param dwFlags Flags (reserved)
/// @return NTSTATUS success or error code
NTSTATUS WINAPI GetInterface(
    _In_ LPCWSTR pszInterface,
    _Out_ NCRYPT_INTERFACE_FN_TABLE** ppFunctionTable,
    _In_ DWORD dwFlags)
{
    if (!supacrypt::ksp::IsDllInitialized())
    {
        return STATUS_NOT_SUPPORTED;
    }

    try
    {
        auto& provider = supacrypt::ksp::WindowsKspProvider::GetInstance();
        return provider.GetInterface(pszInterface, ppFunctionTable, dwFlags);
    }
    catch (const std::exception& e)
    {
        supacrypt::ksp::LogError(L"Exception in GetInterface: %hs", e.what());
        return STATUS_INTERNAL_ERROR;
    }
    catch (...)
    {
        supacrypt::ksp::LogError(L"Unknown exception in GetInterface");
        return STATUS_INTERNAL_ERROR;
    }
}

/// @brief Open provider
/// @param phProvider Pointer to provider handle
/// @param pszProviderName Provider name
/// @param dwFlags Open flags
/// @return NTSTATUS success or error code
NTSTATUS WINAPI OpenProvider(
    _Out_ NCRYPT_PROV_HANDLE* phProvider,
    _In_ LPCWSTR pszProviderName,
    _In_ DWORD dwFlags)
{
    if (!supacrypt::ksp::IsDllInitialized())
    {
        return STATUS_NOT_SUPPORTED;
    }

    try
    {
        auto& provider = supacrypt::ksp::WindowsKspProvider::GetInstance();
        NTSTATUS status = provider.OpenProvider(phProvider, pszProviderName, dwFlags);
        
        if (NT_SUCCESS(status))
        {
            supacrypt::ksp::IncrementReferenceCount();
        }
        
        return status;
    }
    catch (const std::exception& e)
    {
        supacrypt::ksp::LogError(L"Exception in OpenProvider: %hs", e.what());
        return STATUS_INTERNAL_ERROR;
    }
    catch (...)
    {
        supacrypt::ksp::LogError(L"Unknown exception in OpenProvider");
        return STATUS_INTERNAL_ERROR;
    }
}

/// @brief Close provider
/// @param hProvider Provider handle
/// @param dwFlags Close flags
/// @return NTSTATUS success or error code
NTSTATUS WINAPI CloseProvider(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ DWORD dwFlags)
{
    if (!supacrypt::ksp::IsDllInitialized())
    {
        return STATUS_NOT_SUPPORTED;
    }

    try
    {
        auto& provider = supacrypt::ksp::WindowsKspProvider::GetInstance();
        NTSTATUS status = provider.CloseProvider(hProvider, dwFlags);
        
        if (NT_SUCCESS(status))
        {
            supacrypt::ksp::DecrementReferenceCount();
        }
        
        return status;
    }
    catch (const std::exception& e)
    {
        supacrypt::ksp::LogError(L"Exception in CloseProvider: %hs", e.what());
        return STATUS_INTERNAL_ERROR;
    }
    catch (...)
    {
        supacrypt::ksp::LogError(L"Unknown exception in CloseProvider");
        return STATUS_INTERNAL_ERROR;
    }
}

/// @brief Create new key
/// @param hProvider Provider handle
/// @param phKey Pointer to key handle
/// @param pszAlgId Algorithm identifier
/// @param pszKeyName Key name (optional)
/// @param dwLegacyKeySpec Legacy key specification
/// @param dwFlags Creation flags
/// @return NTSTATUS success or error code
NTSTATUS WINAPI CreateKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Out_ NCRYPT_KEY_HANDLE* phKey,
    _In_ LPCWSTR pszAlgId,
    _In_opt_ LPCWSTR pszKeyName,
    _In_ DWORD dwLegacyKeySpec,
    _In_ DWORD dwFlags)
{
    if (!supacrypt::ksp::IsDllInitialized())
    {
        return STATUS_NOT_SUPPORTED;
    }

    try
    {
        auto& provider = supacrypt::ksp::WindowsKspProvider::GetInstance();
        return provider.CreateKey(hProvider, phKey, pszAlgId, pszKeyName, dwLegacyKeySpec, dwFlags);
    }
    catch (const std::exception& e)
    {
        supacrypt::ksp::LogError(L"Exception in CreateKey: %hs", e.what());
        return STATUS_INTERNAL_ERROR;
    }
    catch (...)
    {
        supacrypt::ksp::LogError(L"Unknown exception in CreateKey");
        return STATUS_INTERNAL_ERROR;
    }
}

/// @brief Open existing key
/// @param hProvider Provider handle
/// @param phKey Pointer to key handle
/// @param pszKeyName Key name
/// @param dwLegacyKeySpec Legacy key specification
/// @param dwFlags Open flags
/// @return NTSTATUS success or error code
NTSTATUS WINAPI OpenKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Out_ NCRYPT_KEY_HANDLE* phKey,
    _In_ LPCWSTR pszKeyName,
    _In_ DWORD dwLegacyKeySpec,
    _In_ DWORD dwFlags)
{
    if (!supacrypt::ksp::IsDllInitialized())
    {
        return STATUS_NOT_SUPPORTED;
    }

    try
    {
        auto& provider = supacrypt::ksp::WindowsKspProvider::GetInstance();
        return provider.OpenKey(hProvider, phKey, pszKeyName, dwLegacyKeySpec, dwFlags);
    }
    catch (const std::exception& e)
    {
        supacrypt::ksp::LogError(L"Exception in OpenKey: %hs", e.what());
        return STATUS_INTERNAL_ERROR;
    }
    catch (...)
    {
        supacrypt::ksp::LogError(L"Unknown exception in OpenKey");
        return STATUS_INTERNAL_ERROR;
    }
}

/// @brief Delete key
/// @param hKey Key handle
/// @param dwFlags Delete flags
/// @return NTSTATUS success or error code
NTSTATUS WINAPI DeleteKey(
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_ DWORD dwFlags)
{
    if (!supacrypt::ksp::IsDllInitialized())
    {
        return STATUS_NOT_SUPPORTED;
    }

    try
    {
        auto& provider = supacrypt::ksp::WindowsKspProvider::GetInstance();
        return provider.DeleteKey(hKey, dwFlags);
    }
    catch (const std::exception& e)
    {
        supacrypt::ksp::LogError(L"Exception in DeleteKey: %hs", e.what());
        return STATUS_INTERNAL_ERROR;
    }
    catch (...)
    {
        supacrypt::ksp::LogError(L"Unknown exception in DeleteKey");
        return STATUS_INTERNAL_ERROR;
    }
}

/// @brief Finalize key creation
/// @param hKey Key handle
/// @param dwFlags Finalization flags
/// @return NTSTATUS success or error code
NTSTATUS WINAPI FinalizeKey(
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_ DWORD dwFlags)
{
    if (!supacrypt::ksp::IsDllInitialized())
    {
        return STATUS_NOT_SUPPORTED;
    }

    try
    {
        auto& provider = supacrypt::ksp::WindowsKspProvider::GetInstance();
        return provider.FinalizeKey(hKey, dwFlags);
    }
    catch (const std::exception& e)
    {
        supacrypt::ksp::LogError(L"Exception in FinalizeKey: %hs", e.what());
        return STATUS_INTERNAL_ERROR;
    }
    catch (...)
    {
        supacrypt::ksp::LogError(L"Unknown exception in FinalizeKey");
        return STATUS_INTERNAL_ERROR;
    }
}

/// @brief Sign hash
/// @param hKey Key handle
/// @param pPaddingInfo Padding information
/// @param pbHashValue Hash value to sign
/// @param cbHashValue Size of hash value
/// @param pbSignature Buffer for signature
/// @param cbSignature Size of signature buffer
/// @param pcbResult Actual signature size
/// @param dwFlags Signing flags
/// @return NTSTATUS success or error code
NTSTATUS WINAPI SignHash(
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_opt_ VOID* pPaddingInfo,
    _In_reads_bytes_(cbHashValue) PBYTE pbHashValue,
    _In_ DWORD cbHashValue,
    _Out_writes_bytes_to_opt_(cbSignature, *pcbResult) PBYTE pbSignature,
    _In_ DWORD cbSignature,
    _Out_ DWORD* pcbResult,
    _In_ DWORD dwFlags)
{
    if (!supacrypt::ksp::IsDllInitialized())
    {
        return STATUS_NOT_SUPPORTED;
    }

    try
    {
        auto& provider = supacrypt::ksp::WindowsKspProvider::GetInstance();
        return provider.SignHash(hKey, pPaddingInfo, pbHashValue, cbHashValue,
                                pbSignature, cbSignature, pcbResult, dwFlags);
    }
    catch (const std::exception& e)
    {
        supacrypt::ksp::LogError(L"Exception in SignHash: %hs", e.what());
        return STATUS_INTERNAL_ERROR;
    }
    catch (...)
    {
        supacrypt::ksp::LogError(L"Unknown exception in SignHash");
        return STATUS_INTERNAL_ERROR;
    }
}

/// @brief Verify signature
/// @param hKey Key handle
/// @param pPaddingInfo Padding information
/// @param pbHashValue Hash value
/// @param cbHashValue Size of hash value
/// @param pbSignature Signature to verify
/// @param cbSignature Size of signature
/// @param dwFlags Verification flags
/// @return NTSTATUS success or error code
NTSTATUS WINAPI VerifySignature(
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_opt_ VOID* pPaddingInfo,
    _In_reads_bytes_(cbHashValue) PBYTE pbHashValue,
    _In_ DWORD cbHashValue,
    _In_reads_bytes_(cbSignature) PBYTE pbSignature,
    _In_ DWORD cbSignature,
    _In_ DWORD dwFlags)
{
    if (!supacrypt::ksp::IsDllInitialized())
    {
        return STATUS_NOT_SUPPORTED;
    }

    try
    {
        auto& provider = supacrypt::ksp::WindowsKspProvider::GetInstance();
        return provider.VerifySignature(hKey, pPaddingInfo, pbHashValue, cbHashValue,
                                       pbSignature, cbSignature, dwFlags);
    }
    catch (const std::exception& e)
    {
        supacrypt::ksp::LogError(L"Exception in VerifySignature: %hs", e.what());
        return STATUS_INTERNAL_ERROR;
    }
    catch (...)
    {
        supacrypt::ksp::LogError(L"Unknown exception in VerifySignature");
        return STATUS_INTERNAL_ERROR;
    }
}

// Additional exported functions would continue here...
// For brevity, I'm showing the pattern for the key functions

/// @brief Internal utility function to get KSP version
/// @return Version string
LPCWSTR WINAPI SupacryptKspGetVersion()
{
    return L"1.0.0";
}

} // extern "C"