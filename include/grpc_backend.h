// grpc_backend.h - gRPC backend client for Supacrypt KSP
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include <vector>
#include <chrono>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <thread>

// Forward declarations for gRPC
namespace grpc
{
    class Channel;
    class ClientContext;
    class Status;
}

namespace supacrypt
{
namespace ksp
{

/// @brief gRPC operation result wrapper
template<typename T>
struct GrpcResult
{
    bool success;
    T response;
    std::string errorMessage;
    int errorCode;
    
    GrpcResult() : success(false), errorCode(0) {}
    
    explicit GrpcResult(const T& resp) 
        : success(true), response(resp), errorCode(0) {}
    
    GrpcResult(const std::string& error, int code) 
        : success(false), errorMessage(error), errorCode(code) {}
};

/// @brief Connection pool statistics
struct ConnectionStats
{
    size_t totalConnections;
    size_t activeConnections;
    size_t idleConnections;
    size_t failedConnections;
    std::chrono::milliseconds averageResponseTime;
    size_t totalRequests;
    size_t successfulRequests;
    size_t failedRequests;
};

/// @brief Circuit breaker state
enum class CircuitBreakerState
{
    Closed,     // Normal operation
    Open,       // Blocking requests due to failures
    HalfOpen    // Testing if service is back
};

/// @brief Connection pool configuration
struct ConnectionConfig
{
    std::string endpoint;
    std::string certificatePath;
    std::string privateKeyPath;
    std::string caCertificatePath;
    std::chrono::seconds connectionTimeout{30};
    std::chrono::seconds requestTimeout{60};
    size_t maxConnections{10};
    size_t maxRetries{3};
    std::chrono::seconds retryDelay{1};
    bool enableTls{true};
    bool verifyServerCertificate{true};
    
    // Circuit breaker settings
    size_t failureThreshold{5};
    std::chrono::seconds circuitBreakerTimeout{60};
    size_t halfOpenMaxCalls{3};
};

/// @brief Pooled connection wrapper
class PooledConnection
{
public:
    /// @brief Constructor
    /// @param channel gRPC channel
    /// @param id Connection identifier
    explicit PooledConnection(std::shared_ptr<grpc::Channel> channel, size_t id);

    /// @brief Destructor
    ~PooledConnection();

    /// @brief Get gRPC channel
    /// @return Shared pointer to channel
    std::shared_ptr<grpc::Channel> GetChannel() const { return m_channel; }

    /// @brief Get connection ID
    /// @return Connection identifier
    size_t GetId() const { return m_id; }

    /// @brief Check if connection is healthy
    /// @return true if healthy, false otherwise
    bool IsHealthy() const;

    /// @brief Mark connection as used
    void MarkUsed();

    /// @brief Get last used timestamp
    /// @return Last used time point
    std::chrono::steady_clock::time_point GetLastUsed() const { return m_lastUsed; }

    /// @brief Get creation timestamp
    /// @return Creation time point
    std::chrono::steady_clock::time_point GetCreatedAt() const { return m_createdAt; }

private:
    std::shared_ptr<grpc::Channel> m_channel;
    size_t m_id;
    std::atomic<std::chrono::steady_clock::time_point> m_lastUsed;
    std::chrono::steady_clock::time_point m_createdAt;
    mutable std::mutex m_mutex;
};

/// @brief gRPC backend client with connection pooling and circuit breaker
class GrpcBackendClient
{
public:
    /// @brief Constructor
    /// @param config Connection configuration
    explicit GrpcBackendClient(const ConnectionConfig& config);

    /// @brief Destructor
    ~GrpcBackendClient();

    // Disable copy and move
    GrpcBackendClient(const GrpcBackendClient&) = delete;
    GrpcBackendClient& operator=(const GrpcBackendClient&) = delete;
    GrpcBackendClient(GrpcBackendClient&&) = delete;
    GrpcBackendClient& operator=(GrpcBackendClient&&) = delete;

    /// @brief Initialize client
    /// @return NTSTATUS success or error code
    NTSTATUS Initialize();

    /// @brief Shutdown client
    void Shutdown();

    /// @brief Generate key pair
    /// @param algorithm Algorithm identifier
    /// @param keySize Key size in bits
    /// @param keyId Key identifier
    /// @param keyUsage Key usage flags
    /// @return Operation result
    GrpcResult<std::string> GenerateKey(
        const std::string& algorithm,
        uint32_t keySize,
        const std::string& keyId,
        uint32_t keyUsage);

    /// @brief Sign data
    /// @param keyId Key identifier
    /// @param algorithm Algorithm identifier
    /// @param hashValue Hash value to sign
    /// @param padding Padding scheme
    /// @param hashAlgorithm Hash algorithm
    /// @return Operation result with signature
    GrpcResult<std::vector<uint8_t>> SignData(
        const std::string& keyId,
        const std::string& algorithm,
        const std::vector<uint8_t>& hashValue,
        const std::string& padding,
        const std::string& hashAlgorithm);

    /// @brief Verify signature
    /// @param keyId Key identifier
    /// @param algorithm Algorithm identifier
    /// @param hashValue Hash value
    /// @param signature Signature to verify
    /// @param padding Padding scheme
    /// @param hashAlgorithm Hash algorithm
    /// @return Operation result with verification status
    GrpcResult<bool> VerifySignature(
        const std::string& keyId,
        const std::string& algorithm,
        const std::vector<uint8_t>& hashValue,
        const std::vector<uint8_t>& signature,
        const std::string& padding,
        const std::string& hashAlgorithm);

    /// @brief Encrypt data
    /// @param keyId Key identifier
    /// @param algorithm Algorithm identifier
    /// @param plaintext Data to encrypt
    /// @param padding Padding scheme
    /// @return Operation result with ciphertext
    GrpcResult<std::vector<uint8_t>> EncryptData(
        const std::string& keyId,
        const std::string& algorithm,
        const std::vector<uint8_t>& plaintext,
        const std::string& padding);

    /// @brief Decrypt data
    /// @param keyId Key identifier
    /// @param algorithm Algorithm identifier
    /// @param ciphertext Data to decrypt
    /// @param padding Padding scheme
    /// @return Operation result with plaintext
    GrpcResult<std::vector<uint8_t>> DecryptData(
        const std::string& keyId,
        const std::string& algorithm,
        const std::vector<uint8_t>& ciphertext,
        const std::string& padding);

    /// @brief Get public key
    /// @param keyId Key identifier
    /// @param format Export format
    /// @return Operation result with public key data
    GrpcResult<std::vector<uint8_t>> GetPublicKey(
        const std::string& keyId,
        const std::string& format);

    /// @brief List keys
    /// @param filter Key filter criteria
    /// @return Operation result with key list
    GrpcResult<std::vector<std::string>> ListKeys(const std::string& filter);

    /// @brief Delete key
    /// @param keyId Key identifier
    /// @return Operation result
    GrpcResult<bool> DeleteKey(const std::string& keyId);

    /// @brief Get key metadata
    /// @param keyId Key identifier
    /// @return Operation result with metadata
    GrpcResult<std::string> GetKeyMetadata(const std::string& keyId);

    /// @brief Check if backend is healthy
    /// @return true if healthy, false otherwise
    bool IsHealthy() const;

    /// @brief Get connection statistics
    /// @return Connection statistics
    ConnectionStats GetConnectionStats() const;

    /// @brief Get circuit breaker state
    /// @return Current circuit breaker state
    CircuitBreakerState GetCircuitBreakerState() const;

private:
    /// @brief Create new connection
    /// @return Shared pointer to new connection
    std::shared_ptr<PooledConnection> CreateConnection();

    /// @brief Get connection from pool
    /// @return Shared pointer to connection
    std::shared_ptr<PooledConnection> GetConnection();

    /// @brief Return connection to pool
    /// @param connection Connection to return
    void ReturnConnection(std::shared_ptr<PooledConnection> connection);

    /// @brief Remove connection from pool
    /// @param connection Connection to remove
    void RemoveConnection(std::shared_ptr<PooledConnection> connection);

    /// @brief Create gRPC channel
    /// @return Shared pointer to channel
    std::shared_ptr<grpc::Channel> CreateChannel();

    /// @brief Setup TLS credentials
    /// @return Channel credentials
    std::shared_ptr<grpc::ChannelCredentials> SetupTlsCredentials();

    /// @brief Execute operation with retry logic
    /// @param operation Operation to execute
    /// @return Operation result
    template<typename T>
    GrpcResult<T> ExecuteWithRetry(std::function<GrpcResult<T>()> operation);

    /// @brief Handle gRPC status
    /// @param status gRPC status
    /// @param operation Operation name
    /// @return NTSTATUS error code
    NTSTATUS HandleGrpcStatus(const grpc::Status& status, const std::string& operation);

    /// @brief Update circuit breaker on success
    void OnSuccess();

    /// @brief Update circuit breaker on failure
    void OnFailure();

    /// @brief Check if circuit breaker allows request
    /// @return true if allowed, false otherwise
    bool ShouldAllowRequest();

    /// @brief Convert gRPC status to NTSTATUS
    /// @param status gRPC status
    /// @return NTSTATUS error code
    NTSTATUS ConvertGrpcStatus(const grpc::Status& status);

    /// @brief Cleanup expired connections
    void CleanupExpiredConnections();

    /// @brief Connection pool maintenance worker
    void ConnectionMaintenanceWorker();

private:
    mutable std::mutex m_mutex;
    bool m_initialized;
    bool m_shutdown;
    
    // Configuration
    ConnectionConfig m_config;
    
    // Connection pool
    std::queue<std::shared_ptr<PooledConnection>> m_availableConnections;
    std::vector<std::shared_ptr<PooledConnection>> m_allConnections;
    std::atomic<size_t> m_connectionIdCounter;
    
    // Circuit breaker
    std::atomic<CircuitBreakerState> m_circuitBreakerState;
    std::atomic<size_t> m_failureCount;
    std::atomic<size_t> m_halfOpenCallCount;
    std::chrono::steady_clock::time_point m_lastFailureTime;
    
    // Statistics
    mutable std::mutex m_statsMutex;
    ConnectionStats m_stats;
    std::chrono::steady_clock::time_point m_statsStartTime;
    
    // Maintenance thread
    std::thread m_maintenanceThread;
    std::condition_variable m_maintenanceCondition;
    
    // gRPC service stub (forward declaration handled in implementation)
    std::unique_ptr<void> m_serviceStub;
};

} // namespace ksp
} // namespace supacrypt