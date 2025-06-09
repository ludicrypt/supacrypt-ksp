// logging.h - Logging utilities for Supacrypt KSP
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include <sstream>
#include <mutex>
#include <atomic>

namespace supacrypt
{
namespace ksp
{

/// @brief Log levels
enum class LogLevel : int
{
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warning = 3,
    Error = 4,
    Critical = 5,
    Off = 6
};

/// @brief Log targets
enum class LogTarget : int
{
    None = 0,
    Console = 1,
    File = 2,
    EventLog = 4,
    DebugOutput = 8,
    Syslog = 16,
    All = Console | File | EventLog | DebugOutput
};

/// @brief Log configuration
struct LogConfig
{
    LogLevel level{LogLevel::Info};
    LogTarget targets{LogTarget::File | LogTarget::DebugOutput};
    std::wstring logFilePath{L"C:\\ProgramData\\Supacrypt\\Logs\\supacrypt-ksp.log"};
    std::wstring eventLogSource{L"Supacrypt KSP"};
    size_t maxFileSize{10 * 1024 * 1024}; // 10 MB
    size_t maxBackupFiles{5};
    bool enableTimestamps{true};
    bool enableThreadId{true};
    bool enableProcessId{true};
    bool enableFunctionNames{true};
    bool enableColors{false}; // For console output
    bool rotateOnStartup{false};
};

/// @brief Logger interface
class Logger
{
public:
    /// @brief Virtual destructor
    virtual ~Logger() = default;

    /// @brief Write log message
    /// @param level Log level
    /// @param message Log message
    virtual void Write(LogLevel level, const std::wstring& message) = 0;

    /// @brief Flush pending log messages
    virtual void Flush() = 0;

    /// @brief Check if level is enabled
    /// @param level Log level to check
    /// @return true if enabled, false otherwise
    virtual bool IsEnabled(LogLevel level) const = 0;
};

/// @brief Log manager
class LogManager
{
public:
    /// @brief Get singleton instance
    /// @return Reference to singleton instance
    static LogManager& GetInstance();

    /// @brief Initialize logging
    /// @param config Log configuration
    /// @return true on success, false on failure
    bool Initialize(const LogConfig& config = LogConfig{});

    /// @brief Shutdown logging
    void Shutdown();

    /// @brief Write log message
    /// @param level Log level
    /// @param message Log message
    /// @param function Function name (optional)
    /// @param file File name (optional)
    /// @param line Line number (optional)
    void Log(LogLevel level, const std::wstring& message,
             const std::wstring& function = L"",
             const std::wstring& file = L"",
             int line = 0);

    /// @brief Write formatted log message
    /// @param level Log level
    /// @param format Format string
    /// @param args Format arguments
    template<typename... Args>
    void LogFormat(LogLevel level, const std::wstring& format, Args&&... args)
    {
        if (!IsEnabled(level))
        {
            return;
        }

        try
        {
            std::wstring message = FormatString(format, std::forward<Args>(args)...);
            Log(level, message);
        }
        catch (...)
        {
            // Fallback to simple message if formatting fails
            Log(LogLevel::Error, L"Log formatting failed: " + format);
        }
    }

    /// @brief Check if log level is enabled
    /// @param level Log level to check
    /// @return true if enabled, false otherwise
    bool IsEnabled(LogLevel level) const;

    /// @brief Set log level
    /// @param level New log level
    void SetLogLevel(LogLevel level);

    /// @brief Get current log level
    /// @return Current log level
    LogLevel GetLogLevel() const;

    /// @brief Enable/disable log target
    /// @param target Log target
    /// @param enabled Enable or disable
    void SetTargetEnabled(LogTarget target, bool enabled);

    /// @brief Check if log target is enabled
    /// @param target Log target
    /// @return true if enabled, false otherwise
    bool IsTargetEnabled(LogTarget target) const;

    /// @brief Flush all loggers
    void Flush();

    /// @brief Get current configuration
    /// @return Log configuration
    LogConfig GetConfig() const;

private:
    LogManager() = default;
    ~LogManager() = default;

    // Disable copy and move
    LogManager(const LogManager&) = delete;
    LogManager& operator=(const LogManager&) = delete;
    LogManager(LogManager&&) = delete;
    LogManager& operator=(LogManager&&) = delete;

    /// @brief Create loggers based on configuration
    /// @param config Log configuration
    /// @return true on success, false on failure
    bool CreateLoggers(const LogConfig& config);

    /// @brief Format log message with metadata
    /// @param level Log level
    /// @param message Original message
    /// @param function Function name
    /// @param file File name
    /// @param line Line number
    /// @return Formatted message
    std::wstring FormatMessage(LogLevel level, const std::wstring& message,
                              const std::wstring& function,
                              const std::wstring& file,
                              int line) const;

    /// @brief Get log level name
    /// @param level Log level
    /// @return Level name
    std::wstring GetLogLevelName(LogLevel level) const;

    /// @brief Format string with arguments
    /// @param format Format string
    /// @param args Arguments
    /// @return Formatted string
    template<typename... Args>
    std::wstring FormatString(const std::wstring& format, Args&&... args) const
    {
        if constexpr (sizeof...(args) == 0)
        {
            return format;
        }
        else
        {
            // Use swprintf for formatting
            int size = std::swprintf(nullptr, 0, format.c_str(), args...);
            if (size <= 0)
            {
                return format; // Fallback
            }

            std::vector<wchar_t> buffer(size + 1);
            std::swprintf(buffer.data(), buffer.size(), format.c_str(), args...);
            return std::wstring(buffer.data());
        }
    }

private:
    mutable std::mutex m_mutex;
    std::atomic<bool> m_initialized{false};
    LogConfig m_config;
    std::vector<std::unique_ptr<Logger>> m_loggers;
    std::atomic<LogLevel> m_currentLevel{LogLevel::Info};
    std::atomic<int> m_enabledTargets{static_cast<int>(LogTarget::All)};
};

/// @brief Initialize logging system
/// @param config Log configuration
/// @return true on success, false on failure
bool InitializeLogging(const LogConfig& config = LogConfig{});

/// @brief Shutdown logging system
void ShutdownLogging();

/// @brief Check if logging is initialized
/// @return true if initialized, false otherwise
bool IsLoggingInitialized();

// Logging macros
#define LogTrace(message, ...) \
    supacrypt::ksp::LogManager::GetInstance().LogFormat( \
        supacrypt::ksp::LogLevel::Trace, message, ##__VA_ARGS__)

#define LogDebug(message, ...) \
    supacrypt::ksp::LogManager::GetInstance().LogFormat( \
        supacrypt::ksp::LogLevel::Debug, message, ##__VA_ARGS__)

#define LogInfo(message, ...) \
    supacrypt::ksp::LogManager::GetInstance().LogFormat( \
        supacrypt::ksp::LogLevel::Info, message, ##__VA_ARGS__)

#define LogWarning(message, ...) \
    supacrypt::ksp::LogManager::GetInstance().LogFormat( \
        supacrypt::ksp::LogLevel::Warning, message, ##__VA_ARGS__)

#define LogError(message, ...) \
    supacrypt::ksp::LogManager::GetInstance().LogFormat( \
        supacrypt::ksp::LogLevel::Error, message, ##__VA_ARGS__)

#define LogCritical(message, ...) \
    supacrypt::ksp::LogManager::GetInstance().LogFormat( \
        supacrypt::ksp::LogLevel::Critical, message, ##__VA_ARGS__)

// Conditional logging macros
#define LogTraceIf(condition, message, ...) \
    do { if (condition) LogTrace(message, ##__VA_ARGS__); } while(0)

#define LogDebugIf(condition, message, ...) \
    do { if (condition) LogDebug(message, ##__VA_ARGS__); } while(0)

#define LogInfoIf(condition, message, ...) \
    do { if (condition) LogInfo(message, ##__VA_ARGS__); } while(0)

#define LogWarningIf(condition, message, ...) \
    do { if (condition) LogWarning(message, ##__VA_ARGS__); } while(0)

#define LogErrorIf(condition, message, ...) \
    do { if (condition) LogError(message, ##__VA_ARGS__); } while(0)

#define LogCriticalIf(condition, message, ...) \
    do { if (condition) LogCritical(message, ##__VA_ARGS__); } while(0)

// Function entry/exit logging for debugging
#ifdef SUPACRYPT_DEBUG_LOGGING
#define LogFunctionEntry() \
    LogDebug(L"Entering function: %hs", __FUNCTION__)

#define LogFunctionExit() \
    LogDebug(L"Exiting function: %hs", __FUNCTION__)

#define LogFunctionExitWithStatus(status) \
    LogDebug(L"Exiting function: %hs with status: 0x%08lX", __FUNCTION__, status)
#else
#define LogFunctionEntry() do {} while(0)
#define LogFunctionExit() do {} while(0)
#define LogFunctionExitWithStatus(status) do {} while(0)
#endif

// Performance logging
#ifdef SUPACRYPT_PERFORMANCE_LOGGING
#define LogPerformance(operation, duration) \
    LogInfo(L"Performance: %hs took %lld ms", operation, duration)
#else
#define LogPerformance(operation, duration) do {} while(0)
#endif

} // namespace ksp
} // namespace supacrypt