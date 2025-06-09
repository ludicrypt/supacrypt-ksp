// error_handling.cpp - Error handling implementation for Supacrypt KSP
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#include "error_handling.h"
#include "logging.h"

#include <windows.h>
#include <ntstatus.h>
#include <string>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace supacrypt
{
namespace ksp
{

// Static initialization
thread_local ErrorContext ErrorManager::m_threadErrorContext;

// Error message mappings
const std::unordered_map<KspErrorCode, std::wstring> ErrorManager::s_errorMessages = {
    // Success
    {KspErrorCode::Success, L"Operation completed successfully"},
    
    // General errors (4000-4099)
    {KspErrorCode::InvalidParameter, L"Invalid parameter provided"},
    {KspErrorCode::InvalidHandle, L"Invalid handle provided"},
    {KspErrorCode::OutOfMemory, L"Insufficient memory available"},
    {KspErrorCode::InternalError, L"Internal error occurred"},
    {KspErrorCode::NotSupported, L"Operation not supported"},
    {KspErrorCode::AccessDenied, L"Access denied"},
    {KspErrorCode::InvalidData, L"Invalid data provided"},
    {KspErrorCode::BufferTooSmall, L"Buffer too small"},
    {KspErrorCode::NotFound, L"Item not found"},
    {KspErrorCode::AlreadyExists, L"Item already exists"},
    {KspErrorCode::InvalidState, L"Invalid state"},
    
    // Provider errors (4100-4199)
    {KspErrorCode::ProviderNotInitialized, L"Provider not initialized"},
    {KspErrorCode::ProviderAlreadyInitialized, L"Provider already initialized"},
    {KspErrorCode::ProviderShutdown, L"Provider has been shutdown"},
    {KspErrorCode::InvalidProviderHandle, L"Invalid provider handle"},
    {KspErrorCode::ProviderBusy, L"Provider is busy"},
    
    // Key management errors (4200-4299)
    {KspErrorCode::InvalidKeyHandle, L"Invalid key handle"},
    {KspErrorCode::KeyNotFound, L"Key not found"},
    {KspErrorCode::KeyAlreadyExists, L"Key already exists"},
    {KspErrorCode::KeyNotFinalized, L"Key not finalized"},
    {KspErrorCode::KeyAlreadyFinalized, L"Key already finalized"},
    {KspErrorCode::InvalidKeyType, L"Invalid key type"},
    {KspErrorCode::InvalidKeySize, L"Invalid key size"},
    {KspErrorCode::InvalidKeyUsage, L"Invalid key usage"},
    {KspErrorCode::KeyExpired, L"Key has expired"},
    {KspErrorCode::KeyRevoked, L"Key has been revoked"},
    
    // Algorithm errors (4300-4399)
    {KspErrorCode::InvalidAlgorithm, L"Invalid algorithm"},
    {KspErrorCode::AlgorithmNotSupported, L"Algorithm not supported"},
    {KspErrorCode::InvalidPadding, L"Invalid padding scheme"},
    {KspErrorCode::InvalidHashAlgorithm, L"Invalid hash algorithm"},
    {KspErrorCode::InvalidSignature, L"Invalid signature"},
    {KspErrorCode::InvalidCiphertext, L"Invalid ciphertext"},
    {KspErrorCode::DecryptionFailed, L"Decryption failed"},
    {KspErrorCode::EncryptionFailed, L"Encryption failed"},
    {KspErrorCode::SigningFailed, L"Signing operation failed"},
    {KspErrorCode::VerificationFailed, L"Signature verification failed"},
    
    // Backend communication errors (4400-4499)
    {KspErrorCode::BackendNotAvailable, L"Backend service not available"},
    {KspErrorCode::BackendConnectionFailed, L"Backend connection failed"},
    {KspErrorCode::BackendTimeout, L"Backend operation timed out"},
    {KspErrorCode::BackendAuthenticationFailed, L"Backend authentication failed"},
    {KspErrorCode::BackendError, L"Backend service error"},
    {KspErrorCode::BackendBusy, L"Backend service busy"},
    {KspErrorCode::BackendVersionMismatch, L"Backend version mismatch"},
    
    // Property errors (4500-4599)
    {KspErrorCode::InvalidProperty, L"Invalid property"},
    {KspErrorCode::PropertyNotFound, L"Property not found"},
    {KspErrorCode::PropertyReadOnly, L"Property is read-only"},
    {KspErrorCode::PropertyWriteOnly, L"Property is write-only"},
    {KspErrorCode::InvalidPropertyValue, L"Invalid property value"},
    
    // Registry/Configuration errors (4600-4699)
    {KspErrorCode::RegistryError, L"Registry operation failed"},
    {KspErrorCode::ConfigurationError, L"Configuration error"},
    {KspErrorCode::CertificateError, L"Certificate error"},
    {KspErrorCode::InvalidConfiguration, L"Invalid configuration"},
    
    // Threading/Concurrency errors (4700-4799)
    {KspErrorCode::ThreadingError, L"Threading error"},
    {KspErrorCode::LockTimeout, L"Lock operation timed out"},
    {KspErrorCode::DeadlockDetected, L"Deadlock detected"},
    
    // Resource errors (4800-4899)
    {KspErrorCode::ResourceExhausted, L"Resources exhausted"},
    {KspErrorCode::TooManyHandles, L"Too many handles"},
    {KspErrorCode::TooManyConnections, L"Too many connections"},
    {KspErrorCode::QuotaExceeded, L"Quota exceeded"},
    
    // Validation errors (4900-4999)
    {KspErrorCode::ValidationFailed, L"Validation failed"},
    {KspErrorCode::ChecksumMismatch, L"Checksum mismatch"},
    {KspErrorCode::IntegrityCheckFailed, L"Integrity check failed"},
    {KspErrorCode::TamperingDetected, L"Tampering detected"}
};

// NTSTATUS mapping
const std::unordered_map<KspErrorCode, NTSTATUS> ErrorManager::s_ntStatusMap = {
    // Success
    {KspErrorCode::Success, STATUS_SUCCESS},
    
    // General errors
    {KspErrorCode::InvalidParameter, STATUS_INVALID_PARAMETER},
    {KspErrorCode::InvalidHandle, STATUS_INVALID_HANDLE},
    {KspErrorCode::OutOfMemory, STATUS_NO_MEMORY},
    {KspErrorCode::InternalError, STATUS_INTERNAL_ERROR},
    {KspErrorCode::NotSupported, STATUS_NOT_SUPPORTED},
    {KspErrorCode::AccessDenied, STATUS_ACCESS_DENIED},
    {KspErrorCode::InvalidData, STATUS_INVALID_PARAMETER},
    {KspErrorCode::BufferTooSmall, STATUS_BUFFER_TOO_SMALL},
    {KspErrorCode::NotFound, STATUS_NOT_FOUND},
    {KspErrorCode::AlreadyExists, STATUS_OBJECT_NAME_COLLISION},
    {KspErrorCode::InvalidState, STATUS_INVALID_DEVICE_STATE},
    
    // Provider errors
    {KspErrorCode::ProviderNotInitialized, STATUS_NOT_SUPPORTED},
    {KspErrorCode::ProviderAlreadyInitialized, STATUS_ALREADY_COMPLETE},
    {KspErrorCode::ProviderShutdown, STATUS_SHUTDOWN_IN_PROGRESS},
    {KspErrorCode::InvalidProviderHandle, STATUS_INVALID_HANDLE},
    {KspErrorCode::ProviderBusy, STATUS_DEVICE_BUSY},
    
    // Key management errors
    {KspErrorCode::InvalidKeyHandle, STATUS_INVALID_HANDLE},
    {KspErrorCode::KeyNotFound, STATUS_NOT_FOUND},
    {KspErrorCode::KeyAlreadyExists, STATUS_OBJECT_NAME_COLLISION},
    {KspErrorCode::KeyNotFinalized, STATUS_INVALID_DEVICE_STATE},
    {KspErrorCode::KeyAlreadyFinalized, STATUS_INVALID_DEVICE_STATE},
    {KspErrorCode::InvalidKeyType, STATUS_INVALID_PARAMETER},
    {KspErrorCode::InvalidKeySize, STATUS_INVALID_PARAMETER},
    {KspErrorCode::InvalidKeyUsage, STATUS_INVALID_PARAMETER},
    {KspErrorCode::KeyExpired, STATUS_EXPIRED_HANDLE},
    {KspErrorCode::KeyRevoked, STATUS_REVOCATION_OFFLINE_C},
    
    // Algorithm errors
    {KspErrorCode::InvalidAlgorithm, STATUS_INVALID_PARAMETER},
    {KspErrorCode::AlgorithmNotSupported, STATUS_NOT_SUPPORTED},
    {KspErrorCode::InvalidPadding, STATUS_INVALID_PARAMETER},
    {KspErrorCode::InvalidHashAlgorithm, STATUS_INVALID_PARAMETER},
    {KspErrorCode::InvalidSignature, STATUS_INVALID_SIGNATURE},
    {KspErrorCode::InvalidCiphertext, STATUS_DECRYPTION_FAILED},
    {KspErrorCode::DecryptionFailed, STATUS_DECRYPTION_FAILED},
    {KspErrorCode::EncryptionFailed, STATUS_ENCRYPTION_FAILED},
    {KspErrorCode::SigningFailed, STATUS_ENCRYPTION_FAILED},
    {KspErrorCode::VerificationFailed, STATUS_INVALID_SIGNATURE},
    
    // Backend communication errors
    {KspErrorCode::BackendNotAvailable, STATUS_SERVICE_REQUEST_TIMEOUT},
    {KspErrorCode::BackendConnectionFailed, STATUS_HOST_UNREACHABLE},
    {KspErrorCode::BackendTimeout, STATUS_IO_TIMEOUT},
    {KspErrorCode::BackendAuthenticationFailed, STATUS_AUTHENTICATION_FIREWALL_FAILED},
    {KspErrorCode::BackendError, STATUS_REMOTE_NOT_LISTENING},
    {KspErrorCode::BackendBusy, STATUS_DEVICE_BUSY},
    {KspErrorCode::BackendVersionMismatch, STATUS_REVISION_MISMATCH},
    
    // Property errors
    {KspErrorCode::InvalidProperty, STATUS_INVALID_PARAMETER},
    {KspErrorCode::PropertyNotFound, STATUS_NOT_FOUND},
    {KspErrorCode::PropertyReadOnly, STATUS_MEDIA_WRITE_PROTECTED},
    {KspErrorCode::PropertyWriteOnly, STATUS_INVALID_DEVICE_REQUEST},
    {KspErrorCode::InvalidPropertyValue, STATUS_INVALID_PARAMETER},
    
    // Registry/Configuration errors
    {KspErrorCode::RegistryError, STATUS_REGISTRY_IO_FAILED},
    {KspErrorCode::ConfigurationError, STATUS_INVALID_PARAMETER},
    {KspErrorCode::CertificateError, STATUS_INVALID_SIGNATURE},
    {KspErrorCode::InvalidConfiguration, STATUS_INVALID_PARAMETER},
    
    // Threading/Concurrency errors
    {KspErrorCode::ThreadingError, STATUS_THREAD_IS_TERMINATING},
    {KspErrorCode::LockTimeout, STATUS_TIMEOUT},
    {KspErrorCode::DeadlockDetected, STATUS_POSSIBLE_DEADLOCK},
    
    // Resource errors
    {KspErrorCode::ResourceExhausted, STATUS_INSUFFICIENT_RESOURCES},
    {KspErrorCode::TooManyHandles, STATUS_TOO_MANY_OPENED_FILES},
    {KspErrorCode::TooManyConnections, STATUS_TOO_MANY_LINKS},
    {KspErrorCode::QuotaExceeded, STATUS_QUOTA_EXCEEDED},
    
    // Validation errors
    {KspErrorCode::ValidationFailed, STATUS_DATA_ERROR},
    {KspErrorCode::ChecksumMismatch, STATUS_CRC_ERROR},
    {KspErrorCode::IntegrityCheckFailed, STATUS_DATA_ERROR},
    {KspErrorCode::TamperingDetected, STATUS_DATA_ERROR}
};

ErrorManager& ErrorManager::GetInstance()
{
    static ErrorManager instance;
    return instance;
}

void ErrorManager::SetLastError(
    KspErrorCode errorCode,
    const std::wstring& message,
    const std::wstring& function,
    const std::wstring& file,
    int line)
{
    ErrorContext& context = GetThreadErrorContext();
    
    context.errorCode = errorCode;
    context.ntStatus = ConvertToNtStatus(errorCode);
    context.message = message;
    context.function = function;
    context.file = file;
    context.line = line;
    context.threadId = GetCurrentThreadId();
    context.timestamp = std::chrono::system_clock::now();
    context.additionalInfo.clear();
    
    // Log the error
    if (errorCode != KspErrorCode::Success)
    {
        LogError(L"KSP Error [%d]: %s in %s:%d", 
                static_cast<DWORD>(errorCode), 
                message.c_str(),
                function.empty() ? L"<unknown>" : function.c_str(),
                line);
    }
}

void ErrorManager::SetLastError(
    KspErrorCode errorCode,
    const std::wstring& message,
    const std::wstring& additionalInfo,
    const std::wstring& function,
    const std::wstring& file,
    int line)
{
    SetLastError(errorCode, message, function, file, line);
    GetThreadErrorContext().additionalInfo = additionalInfo;
}

ErrorContext ErrorManager::GetLastError() const
{
    return GetThreadErrorContext();
}

void ErrorManager::ClearLastError()
{
    ErrorContext& context = GetThreadErrorContext();
    context.errorCode = KspErrorCode::Success;
    context.ntStatus = STATUS_SUCCESS;
    context.message.clear();
    context.function.clear();
    context.file.clear();
    context.line = 0;
    context.threadId = 0;
    context.timestamp = std::chrono::system_clock::time_point{};
    context.additionalInfo.clear();
}

NTSTATUS ErrorManager::ConvertToNtStatus(KspErrorCode errorCode)
{
    auto iter = s_ntStatusMap.find(errorCode);
    if (iter != s_ntStatusMap.end())
    {
        return iter->second;
    }
    
    // Default mapping for unknown errors
    return STATUS_INTERNAL_ERROR;
}

KspErrorCode ErrorManager::ConvertFromNtStatus(NTSTATUS ntStatus)
{
    // Reverse lookup
    for (const auto& pair : s_ntStatusMap)
    {
        if (pair.second == ntStatus)
        {
            return pair.first;
        }
    }
    
    // Map common NTSTATUS codes
    switch (ntStatus)
    {
    case STATUS_SUCCESS:
        return KspErrorCode::Success;
    case STATUS_INVALID_PARAMETER:
        return KspErrorCode::InvalidParameter;
    case STATUS_INVALID_HANDLE:
        return KspErrorCode::InvalidHandle;
    case STATUS_NO_MEMORY:
        return KspErrorCode::OutOfMemory;
    case STATUS_NOT_SUPPORTED:
        return KspErrorCode::NotSupported;
    case STATUS_ACCESS_DENIED:
        return KspErrorCode::AccessDenied;
    case STATUS_BUFFER_TOO_SMALL:
        return KspErrorCode::BufferTooSmall;
    case STATUS_NOT_FOUND:
        return KspErrorCode::NotFound;
    case STATUS_OBJECT_NAME_COLLISION:
        return KspErrorCode::AlreadyExists;
    default:
        return KspErrorCode::InternalError;
    }
}

KspErrorCode ErrorManager::ConvertFromWinError(DWORD winError)
{
    switch (winError)
    {
    case ERROR_SUCCESS:
        return KspErrorCode::Success;
    case ERROR_INVALID_PARAMETER:
    case ERROR_INVALID_DATA:
        return KspErrorCode::InvalidParameter;
    case ERROR_INVALID_HANDLE:
        return KspErrorCode::InvalidHandle;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:
        return KspErrorCode::OutOfMemory;
    case ERROR_NOT_SUPPORTED:
        return KspErrorCode::NotSupported;
    case ERROR_ACCESS_DENIED:
        return KspErrorCode::AccessDenied;
    case ERROR_INSUFFICIENT_BUFFER:
    case ERROR_MORE_DATA:
        return KspErrorCode::BufferTooSmall;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_NOT_FOUND:
        return KspErrorCode::NotFound;
    case ERROR_ALREADY_EXISTS:
    case ERROR_FILE_EXISTS:
        return KspErrorCode::AlreadyExists;
    case ERROR_INVALID_STATE:
        return KspErrorCode::InvalidState;
    case ERROR_TIMEOUT:
        return KspErrorCode::BackendTimeout;
    case ERROR_BUSY:
        return KspErrorCode::ProviderBusy;
    default:
        return KspErrorCode::InternalError;
    }
}

std::wstring ErrorManager::GetErrorMessage(KspErrorCode errorCode)
{
    auto iter = s_errorMessages.find(errorCode);
    if (iter != s_errorMessages.end())
    {
        return iter->second;
    }
    
    return L"Unknown error";
}

bool ErrorManager::IsSuccess(KspErrorCode errorCode)
{
    return errorCode == KspErrorCode::Success;
}

bool ErrorManager::IsCritical(KspErrorCode errorCode)
{
    switch (errorCode)
    {
    case KspErrorCode::OutOfMemory:
    case KspErrorCode::InternalError:
    case KspErrorCode::ProviderShutdown:
    case KspErrorCode::BackendNotAvailable:
    case KspErrorCode::TamperingDetected:
    case KspErrorCode::ResourceExhausted:
        return true;
    default:
        return false;
    }
}

ErrorContext& ErrorManager::GetThreadErrorContext() const
{
    return m_threadErrorContext;
}

// Global functions

static std::atomic<bool> g_errorHandlingInitialized{false};

bool InitializeErrorHandling()
{
    if (g_errorHandlingInitialized.exchange(true))
    {
        return true; // Already initialized
    }
    
    try
    {
        // Initialize the error manager singleton
        ErrorManager::GetInstance();
        
        LogInfo(L"Error handling system initialized");
        return true;
    }
    catch (const std::exception& e)
    {
        LogError(L"Failed to initialize error handling: %hs", e.what());
        g_errorHandlingInitialized = false;
        return false;
    }
}

void ShutdownErrorHandling()
{
    if (!g_errorHandlingInitialized.exchange(false))
    {
        return; // Not initialized
    }
    
    LogInfo(L"Error handling system shutdown");
}

// Validation helper functions

bool ValidateHandle(NCRYPT_HANDLE handle, const std::wstring& handleType)
{
    if (handle == 0)
    {
        SET_KSP_ERROR(KspErrorCode::InvalidHandle, 
                     L"Null handle provided for " + handleType);
        return false;
    }
    
    return true;
}

bool ValidateParameter(const void* pointer, const std::wstring& parameterName)
{
    if (pointer == nullptr)
    {
        SET_KSP_ERROR(KspErrorCode::InvalidParameter, 
                     L"Null pointer provided for " + parameterName);
        return false;
    }
    
    return true;
}

bool ValidateBuffer(const void* buffer, DWORD bufferSize, DWORD minSize, 
                   const std::wstring& parameterName)
{
    if (buffer == nullptr && bufferSize > 0)
    {
        SET_KSP_ERROR(KspErrorCode::InvalidParameter, 
                     L"Null buffer with non-zero size for " + parameterName);
        return false;
    }
    
    if (buffer != nullptr && bufferSize < minSize)
    {
        SET_KSP_ERROR(KspErrorCode::BufferTooSmall, 
                     L"Buffer too small for " + parameterName);
        return false;
    }
    
    return true;
}

bool ValidateFlags(DWORD flags, DWORD validFlags, const std::wstring& parameterName)
{
    if ((flags & ~validFlags) != 0)
    {
        SET_KSP_ERROR(KspErrorCode::InvalidParameter, 
                     L"Invalid flags provided for " + parameterName);
        return false;
    }
    
    return true;
}

bool ValidateString(LPCWSTR str, DWORD maxLength, const std::wstring& parameterName)
{
    if (str == nullptr)
    {
        SET_KSP_ERROR(KspErrorCode::InvalidParameter, 
                     L"Null string provided for " + parameterName);
        return false;
    }
    
    size_t length = wcslen(str);
    if (length > maxLength)
    {
        SET_KSP_ERROR(KspErrorCode::InvalidParameter, 
                     L"String too long for " + parameterName);
        return false;
    }
    
    return true;
}

} // namespace ksp
} // namespace supacrypt