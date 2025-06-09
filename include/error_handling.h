// error_handling.h - Error handling for Supacrypt KSP
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <windows.h>
#include <ntstatus.h>
#include <string>
#include <unordered_map>
#include <mutex>

namespace supacrypt
{
namespace ksp
{

/// @brief KSP-specific error codes (4000-4999 range)
enum class KspErrorCode : DWORD
{
    // Success
    Success = 0,
    
    // General errors (4000-4099)
    InvalidParameter = 4000,
    InvalidHandle = 4001,
    OutOfMemory = 4002,
    InternalError = 4003,
    NotSupported = 4004,
    AccessDenied = 4005,
    InvalidData = 4006,
    BufferTooSmall = 4007,
    NotFound = 4008,
    AlreadyExists = 4009,
    InvalidState = 4010,
    
    // Provider errors (4100-4199)
    ProviderNotInitialized = 4100,
    ProviderAlreadyInitialized = 4101,
    ProviderShutdown = 4102,
    InvalidProviderHandle = 4103,
    ProviderBusy = 4104,
    
    // Key management errors (4200-4299)
    InvalidKeyHandle = 4200,
    KeyNotFound = 4201,
    KeyAlreadyExists = 4202,
    KeyNotFinalized = 4203,
    KeyAlreadyFinalized = 4204,
    InvalidKeyType = 4205,
    InvalidKeySize = 4206,
    InvalidKeyUsage = 4207,
    KeyExpired = 4208,
    KeyRevoked = 4209,
    
    // Algorithm errors (4300-4399)
    InvalidAlgorithm = 4300,
    AlgorithmNotSupported = 4301,
    InvalidPadding = 4302,
    InvalidHashAlgorithm = 4303,
    InvalidSignature = 4304,
    InvalidCiphertext = 4305,
    DecryptionFailed = 4306,
    EncryptionFailed = 4307,
    SigningFailed = 4308,
    VerificationFailed = 4309,
    
    // Backend communication errors (4400-4499)
    BackendNotAvailable = 4400,
    BackendConnectionFailed = 4401,
    BackendTimeout = 4402,
    BackendAuthenticationFailed = 4403,
    BackendError = 4404,
    BackendBusy = 4405,
    BackendVersionMismatch = 4406,
    
    // Property errors (4500-4599)
    InvalidProperty = 4500,
    PropertyNotFound = 4501,
    PropertyReadOnly = 4502,
    PropertyWriteOnly = 4503,
    InvalidPropertyValue = 4504,
    
    // Registry/Configuration errors (4600-4699)
    RegistryError = 4600,
    ConfigurationError = 4601,
    CertificateError = 4602,
    InvalidConfiguration = 4603,
    
    // Threading/Concurrency errors (4700-4799)
    ThreadingError = 4700,
    LockTimeout = 4701,
    DeadlockDetected = 4702,
    
    // Resource errors (4800-4899)
    ResourceExhausted = 4800,
    TooManyHandles = 4801,
    TooManyConnections = 4802,
    QuotaExceeded = 4803,
    
    // Validation errors (4900-4999)
    ValidationFailed = 4900,
    ChecksumMismatch = 4901,
    IntegrityCheckFailed = 4902,
    TamperingDetected = 4903
};

/// @brief Error context information
struct ErrorContext
{
    KspErrorCode errorCode;
    NTSTATUS ntStatus;
    std::wstring message;
    std::wstring function;
    std::wstring file;
    int line;
    DWORD threadId;
    std::chrono::system_clock::time_point timestamp;
    std::wstring additionalInfo;
};

/// @brief Error manager for thread-safe error handling
class ErrorManager
{
public:
    /// @brief Get singleton instance
    /// @return Reference to singleton instance
    static ErrorManager& GetInstance();

    /// @brief Set last error for current thread
    /// @param errorCode KSP error code
    /// @param message Error message
    /// @param function Function name
    /// @param file File name
    /// @param line Line number
    void SetLastError(
        KspErrorCode errorCode,
        const std::wstring& message,
        const std::wstring& function = L"",
        const std::wstring& file = L"",
        int line = 0);

    /// @brief Set last error with additional info
    /// @param errorCode KSP error code
    /// @param message Error message
    /// @param additionalInfo Additional error information
    /// @param function Function name
    /// @param file File name
    /// @param line Line number
    void SetLastError(
        KspErrorCode errorCode,
        const std::wstring& message,
        const std::wstring& additionalInfo,
        const std::wstring& function = L"",
        const std::wstring& file = L"",
        int line = 0);

    /// @brief Get last error for current thread
    /// @return Error context
    ErrorContext GetLastError() const;

    /// @brief Clear last error for current thread
    void ClearLastError();

    /// @brief Convert KSP error code to NTSTATUS
    /// @param errorCode KSP error code
    /// @return NTSTATUS equivalent
    static NTSTATUS ConvertToNtStatus(KspErrorCode errorCode);

    /// @brief Convert NTSTATUS to KSP error code
    /// @param ntStatus NTSTATUS code
    /// @return KSP error code equivalent
    static KspErrorCode ConvertFromNtStatus(NTSTATUS ntStatus);

    /// @brief Convert Windows error code to KSP error code
    /// @param winError Windows error code
    /// @return KSP error code equivalent
    static KspErrorCode ConvertFromWinError(DWORD winError);

    /// @brief Get error message for error code
    /// @param errorCode KSP error code
    /// @return Error message
    static std::wstring GetErrorMessage(KspErrorCode errorCode);

    /// @brief Check if error code indicates success
    /// @param errorCode KSP error code
    /// @return true if success, false otherwise
    static bool IsSuccess(KspErrorCode errorCode);

    /// @brief Check if error code is critical
    /// @param errorCode KSP error code
    /// @return true if critical, false otherwise
    static bool IsCritical(KspErrorCode errorCode);

private:
    ErrorManager() = default;
    ~ErrorManager() = default;

    // Disable copy and move
    ErrorManager(const ErrorManager&) = delete;
    ErrorManager& operator=(const ErrorManager&) = delete;
    ErrorManager(ErrorManager&&) = delete;
    ErrorManager& operator=(ErrorManager&&) = delete;

    /// @brief Get error context for current thread
    /// @return Reference to error context
    ErrorContext& GetThreadErrorContext() const;

private:
    mutable std::mutex m_mutex;
    mutable thread_local ErrorContext m_threadErrorContext;
    
    // Error message mappings
    static const std::unordered_map<KspErrorCode, std::wstring> s_errorMessages;
    static const std::unordered_map<KspErrorCode, NTSTATUS> s_ntStatusMap;
};

/// @brief Initialize error handling system
/// @return true on success, false on failure
bool InitializeErrorHandling();

/// @brief Shutdown error handling system
void ShutdownErrorHandling();

/// @brief Macro for setting error with file/line information
#define SET_KSP_ERROR(code, message) \
    supacrypt::ksp::ErrorManager::GetInstance().SetLastError( \
        code, message, __FUNCTIONW__, __FILEW__, __LINE__)

/// @brief Macro for setting error with additional info
#define SET_KSP_ERROR_INFO(code, message, info) \
    supacrypt::ksp::ErrorManager::GetInstance().SetLastError( \
        code, message, info, __FUNCTIONW__, __FILEW__, __LINE__)

/// @brief Macro for getting last error
#define GET_KSP_ERROR() \
    supacrypt::ksp::ErrorManager::GetInstance().GetLastError()

/// @brief Macro for clearing last error
#define CLEAR_KSP_ERROR() \
    supacrypt::ksp::ErrorManager::GetInstance().ClearLastError()

/// @brief Macro for converting KSP error to NTSTATUS
#define KSP_TO_NTSTATUS(code) \
    supacrypt::ksp::ErrorManager::ConvertToNtStatus(code)

/// @brief Macro for converting NTSTATUS to KSP error
#define NTSTATUS_TO_KSP(status) \
    supacrypt::ksp::ErrorManager::ConvertFromNtStatus(status)

/// @brief Macro for converting Windows error to KSP error
#define WINERROR_TO_KSP(error) \
    supacrypt::ksp::ErrorManager::ConvertFromWinError(error)

/// @brief Helper function to validate handle
/// @param handle Handle to validate
/// @param handleType Expected handle type name
/// @return true if valid, false otherwise
bool ValidateHandle(NCRYPT_HANDLE handle, const std::wstring& handleType);

/// @brief Helper function to validate pointer parameter
/// @param pointer Pointer to validate
/// @param parameterName Parameter name for error reporting
/// @return true if valid, false otherwise
bool ValidateParameter(const void* pointer, const std::wstring& parameterName);

/// @brief Helper function to validate buffer and size
/// @param buffer Buffer pointer
/// @param bufferSize Buffer size
/// @param minSize Minimum required size
/// @param parameterName Parameter name for error reporting
/// @return true if valid, false otherwise
bool ValidateBuffer(const void* buffer, DWORD bufferSize, DWORD minSize, 
                   const std::wstring& parameterName);

/// @brief Helper function to validate flags
/// @param flags Flags to validate
/// @param validFlags Valid flag mask
/// @param parameterName Parameter name for error reporting
/// @return true if valid, false otherwise
bool ValidateFlags(DWORD flags, DWORD validFlags, const std::wstring& parameterName);

/// @brief Helper function to validate string parameter
/// @param str String to validate
/// @param maxLength Maximum allowed length
/// @param parameterName Parameter name for error reporting
/// @return true if valid, false otherwise
bool ValidateString(LPCWSTR str, DWORD maxLength, const std::wstring& parameterName);

} // namespace ksp
} // namespace supacrypt