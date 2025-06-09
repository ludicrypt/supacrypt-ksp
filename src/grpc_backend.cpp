// grpc_backend.cpp - gRPC backend client implementation for Supacrypt KSP
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#include "grpc_backend.h"
#include "error_handling.h"
#include "logging.h"

// gRPC includes (would be generated from protobuf)
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/create_channel.h>

// Generated protobuf includes
#include "supacrypt.pb.h"
#include "supacrypt.grpc.pb.h"

#include <windows.h>
#include <fstream>
#include <chrono>
#include <random>
#include <algorithm>

namespace supacrypt
{
namespace ksp
{

// PooledConnection implementation

PooledConnection::PooledConnection(std::shared_ptr<grpc::Channel> channel, size_t id)
    : m_channel(channel)
    , m_id(id)
    , m_createdAt(std::chrono::steady_clock::now())
{
    m_lastUsed.store(m_createdAt);
    LogDebug(L"Created pooled connection: %zu", m_id);
}

PooledConnection::~PooledConnection()
{
    LogDebug(L"Destroyed pooled connection: %zu", m_id);
}

bool PooledConnection::IsHealthy() const
{
    if (!m_channel)
    {
        return false;
    }
    
    auto state = m_channel->GetState(false);
    return state == GRPC_CHANNEL_READY || state == GRPC_CHANNEL_IDLE;
}

void PooledConnection::MarkUsed()
{
    m_lastUsed.store(std::chrono::steady_clock::now());
}

// GrpcBackendClient implementation

GrpcBackendClient::GrpcBackendClient(const ConnectionConfig& config)
    : m_initialized(false)
    , m_shutdown(false)
    , m_config(config)
    , m_connectionIdCounter(1)
    , m_circuitBreakerState(CircuitBreakerState::Closed)
    , m_failureCount(0)
    , m_halfOpenCallCount(0)
    , m_statsStartTime(std::chrono::steady_clock::now())
{
    LogFunctionEntry();
    
    // Initialize statistics
    memset(&m_stats, 0, sizeof(m_stats));
    
    LogInfo(L"GrpcBackendClient created with endpoint: %hs", m_config.endpoint.c_str());
}

GrpcBackendClient::~GrpcBackendClient()
{
    LogFunctionEntry();
    Shutdown();
}

NTSTATUS GrpcBackendClient::Initialize()
{
    LogFunctionEntry();
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized)
    {
        LogInfo(L"gRPC backend client already initialized");
        return STATUS_SUCCESS;
    }

    try
    {
        LogInfo(L"Initializing gRPC backend client...");

        // Validate configuration
        if (m_config.endpoint.empty())
        {
            SET_KSP_ERROR(KspErrorCode::InvalidConfiguration, L"Empty endpoint in configuration");
            return KSP_TO_NTSTATUS(KspErrorCode::InvalidConfiguration);
        }

        // Create initial connections
        for (size_t i = 0; i < std::min(m_config.maxConnections, size_t(2)); ++i)
        {
            auto connection = CreateConnection();
            if (connection && connection->IsHealthy())
            {
                m_availableConnections.push(connection);
                m_allConnections.push_back(connection);
                m_stats.totalConnections++;
            }
            else
            {
                LogWarning(L"Failed to create initial connection %zu", i);
            }
        }

        if (m_availableConnections.empty())
        {
            SET_KSP_ERROR(KspErrorCode::BackendConnectionFailed, L"Failed to create any connections");
            return KSP_TO_NTSTATUS(KspErrorCode::BackendConnectionFailed);
        }

        // Start maintenance thread
        m_maintenanceThread = std::thread(&GrpcBackendClient::ConnectionMaintenanceWorker, this);

        m_initialized = true;
        LogInfo(L"gRPC backend client initialized successfully with %zu connections", 
                m_availableConnections.size());
        LogFunctionExitWithStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }
    catch (const std::exception& e)
    {
        SET_KSP_ERROR(KspErrorCode::InternalError, L"Exception during gRPC client initialization");
        LogError(L"Exception in GrpcBackendClient::Initialize: %hs", e.what());
        LogFunctionExitWithStatus(STATUS_INTERNAL_ERROR);
        return STATUS_INTERNAL_ERROR;
    }
}

void GrpcBackendClient::Shutdown()
{
    LogFunctionEntry();
    
    std::unique_lock<std::mutex> lock(m_mutex);
    
    if (!m_initialized || m_shutdown)
    {
        LogDebug(L"gRPC backend client not initialized or already shutdown");
        return;
    }

    try
    {
        LogInfo(L"Shutting down gRPC backend client...");

        m_shutdown = true;
        lock.unlock();

        // Signal maintenance thread to stop
        m_maintenanceCondition.notify_all();
        
        if (m_maintenanceThread.joinable())
        {
            m_maintenanceThread.join();
        }

        lock.lock();

        // Clear all connections
        while (!m_availableConnections.empty())
        {
            m_availableConnections.pop();
        }
        m_allConnections.clear();

        m_initialized = false;
        LogInfo(L"gRPC backend client shutdown completed");
    }
    catch (const std::exception& e)
    {
        LogError(L"Exception during gRPC client shutdown: %hs", e.what());
    }
    
    LogFunctionExit();
}

GrpcResult<std::string> GrpcBackendClient::GenerateKey(
    const std::string& algorithm,
    uint32_t keySize,
    const std::string& keyId,
    uint32_t keyUsage)
{
    LogFunctionEntry();
    
    if (!m_initialized)
    {
        return GrpcResult<std::string>("Client not initialized", 
                                      static_cast<int>(KspErrorCode::ProviderNotInitialized));
    }

    if (!ShouldAllowRequest())
    {
        return GrpcResult<std::string>("Circuit breaker open", 
                                      static_cast<int>(KspErrorCode::BackendNotAvailable));
    }

    return ExecuteWithRetry<std::string>([&]() -> GrpcResult<std::string> {
        auto connection = GetConnection();
        if (!connection)
        {
            return GrpcResult<std::string>("No available connections", 
                                          static_cast<int>(KspErrorCode::BackendConnectionFailed));
        }

        try
        {
            // Create gRPC stub
            auto stub = supacrypt::SupacryptService::NewStub(connection->GetChannel());
            
            // Prepare request
            supacrypt::GenerateKeyRequest request;
            request.set_algorithm(algorithm);
            request.set_key_size(keySize);
            request.set_key_id(keyId);
            request.set_key_usage(keyUsage);

            // Create context with timeout
            grpc::ClientContext context;
            auto deadline = std::chrono::system_clock::now() + m_config.requestTimeout;
            context.set_deadline(deadline);

            // Execute call
            supacrypt::GenerateKeyResponse response;
            auto startTime = std::chrono::steady_clock::now();
            
            grpc::Status status = stub->GenerateKey(&context, request, &response);
            
            auto endTime = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
            
            // Update statistics
            {
                std::lock_guard<std::mutex> statsLock(m_statsMutex);
                m_stats.totalRequests++;
                m_stats.averageResponseTime = 
                    std::chrono::milliseconds((m_stats.averageResponseTime.count() + duration.count()) / 2);
            }

            connection->MarkUsed();
            ReturnConnection(connection);

            if (status.ok())
            {
                OnSuccess();
                LogInfo(L"Key generated successfully: %hs", keyId.c_str());
                return GrpcResult<std::string>(response.key_id());
            }
            else
            {
                OnFailure();
                LogError(L"GenerateKey failed: %hs", status.error_message().c_str());
                return GrpcResult<std::string>(status.error_message(), status.error_code());
            }
        }
        catch (const std::exception& e)
        {
            OnFailure();
            RemoveConnection(connection);
            LogError(L"Exception in GenerateKey: %hs", e.what());
            return GrpcResult<std::string>("Exception during call", 
                                          static_cast<int>(KspErrorCode::InternalError));
        }
    });
}

GrpcResult<std::vector<uint8_t>> GrpcBackendClient::SignData(
    const std::string& keyId,
    const std::string& algorithm,
    const std::vector<uint8_t>& hashValue,
    const std::string& padding,
    const std::string& hashAlgorithm)
{
    LogFunctionEntry();
    
    if (!m_initialized)
    {
        return GrpcResult<std::vector<uint8_t>>("Client not initialized", 
                                               static_cast<int>(KspErrorCode::ProviderNotInitialized));
    }

    if (!ShouldAllowRequest())
    {
        return GrpcResult<std::vector<uint8_t>>("Circuit breaker open", 
                                               static_cast<int>(KspErrorCode::BackendNotAvailable));
    }

    return ExecuteWithRetry<std::vector<uint8_t>>([&]() -> GrpcResult<std::vector<uint8_t>> {
        auto connection = GetConnection();
        if (!connection)
        {
            return GrpcResult<std::vector<uint8_t>>("No available connections", 
                                                   static_cast<int>(KspErrorCode::BackendConnectionFailed));
        }

        try
        {
            // Create gRPC stub
            auto stub = supacrypt::SupacryptService::NewStub(connection->GetChannel());
            
            // Prepare request
            supacrypt::SignDataRequest request;
            request.set_key_id(keyId);
            request.set_algorithm(algorithm);
            request.set_data(hashValue.data(), hashValue.size());
            request.set_padding_scheme(padding);
            request.set_hash_algorithm(hashAlgorithm);

            // Create context with timeout
            grpc::ClientContext context;
            auto deadline = std::chrono::system_clock::now() + m_config.requestTimeout;
            context.set_deadline(deadline);

            // Execute call
            supacrypt::SignDataResponse response;
            auto startTime = std::chrono::steady_clock::now();
            
            grpc::Status status = stub->SignData(&context, request, &response);
            
            auto endTime = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
            
            // Update statistics
            {
                std::lock_guard<std::mutex> statsLock(m_statsMutex);
                m_stats.totalRequests++;
                m_stats.averageResponseTime = 
                    std::chrono::milliseconds((m_stats.averageResponseTime.count() + duration.count()) / 2);
            }

            connection->MarkUsed();
            ReturnConnection(connection);

            if (status.ok())
            {
                OnSuccess();
                LogInfo(L"Data signed successfully for key: %hs", keyId.c_str());
                
                const std::string& signature = response.signature();
                return GrpcResult<std::vector<uint8_t>>(
                    std::vector<uint8_t>(signature.begin(), signature.end()));
            }
            else
            {
                OnFailure();
                LogError(L"SignData failed: %hs", status.error_message().c_str());
                return GrpcResult<std::vector<uint8_t>>(status.error_message(), status.error_code());
            }
        }
        catch (const std::exception& e)
        {
            OnFailure();
            RemoveConnection(connection);
            LogError(L"Exception in SignData: %hs", e.what());
            return GrpcResult<std::vector<uint8_t>>("Exception during call", 
                                                   static_cast<int>(KspErrorCode::InternalError));
        }
    });
}

GrpcResult<bool> GrpcBackendClient::VerifySignature(
    const std::string& keyId,
    const std::string& algorithm,
    const std::vector<uint8_t>& hashValue,
    const std::vector<uint8_t>& signature,
    const std::string& padding,
    const std::string& hashAlgorithm)
{
    LogFunctionEntry();
    
    if (!m_initialized)
    {
        return GrpcResult<bool>("Client not initialized", 
                               static_cast<int>(KspErrorCode::ProviderNotInitialized));
    }

    if (!ShouldAllowRequest())
    {
        return GrpcResult<bool>("Circuit breaker open", 
                               static_cast<int>(KspErrorCode::BackendNotAvailable));
    }

    return ExecuteWithRetry<bool>([&]() -> GrpcResult<bool> {
        auto connection = GetConnection();
        if (!connection)
        {
            return GrpcResult<bool>("No available connections", 
                                   static_cast<int>(KspErrorCode::BackendConnectionFailed));
        }

        try
        {
            // Create gRPC stub
            auto stub = supacrypt::SupacryptService::NewStub(connection->GetChannel());
            
            // Prepare request
            supacrypt::VerifySignatureRequest request;
            request.set_key_id(keyId);
            request.set_algorithm(algorithm);
            request.set_data(hashValue.data(), hashValue.size());
            request.set_signature(signature.data(), signature.size());
            request.set_padding_scheme(padding);
            request.set_hash_algorithm(hashAlgorithm);

            // Create context with timeout
            grpc::ClientContext context;
            auto deadline = std::chrono::system_clock::now() + m_config.requestTimeout;
            context.set_deadline(deadline);

            // Execute call
            supacrypt::VerifySignatureResponse response;
            auto startTime = std::chrono::steady_clock::now();
            
            grpc::Status status = stub->VerifySignature(&context, request, &response);
            
            auto endTime = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
            
            // Update statistics
            {
                std::lock_guard<std::mutex> statsLock(m_statsMutex);
                m_stats.totalRequests++;
                m_stats.averageResponseTime = 
                    std::chrono::milliseconds((m_stats.averageResponseTime.count() + duration.count()) / 2);
            }

            connection->MarkUsed();
            ReturnConnection(connection);

            if (status.ok())
            {
                OnSuccess();
                LogInfo(L"Signature verification completed for key: %hs, valid: %s", 
                        keyId.c_str(), response.is_valid() ? "true" : "false");
                return GrpcResult<bool>(response.is_valid());
            }
            else
            {
                OnFailure();
                LogError(L"VerifySignature failed: %hs", status.error_message().c_str());
                return GrpcResult<bool>(status.error_message(), status.error_code());
            }
        }
        catch (const std::exception& e)
        {
            OnFailure();
            RemoveConnection(connection);
            LogError(L"Exception in VerifySignature: %hs", e.what());
            return GrpcResult<bool>("Exception during call", 
                                   static_cast<int>(KspErrorCode::InternalError));
        }
    });
}

// Additional operation implementations would follow similar patterns...

bool GrpcBackendClient::IsHealthy() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized || m_shutdown)
    {
        return false;
    }
    
    // Check if we have any healthy connections
    for (const auto& connection : m_allConnections)
    {
        if (connection && connection->IsHealthy())
        {
            return true;
        }
    }
    
    return false;
}

ConnectionStats GrpcBackendClient::GetConnectionStats() const
{
    std::lock_guard<std::mutex> statsLock(m_statsMutex);
    
    ConnectionStats stats = m_stats;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    stats.totalConnections = m_allConnections.size();
    stats.activeConnections = m_allConnections.size() - m_availableConnections.size();
    stats.idleConnections = m_availableConnections.size();
    
    return stats;
}

CircuitBreakerState GrpcBackendClient::GetCircuitBreakerState() const
{
    return m_circuitBreakerState.load();
}

// Private helper methods

std::shared_ptr<PooledConnection> GrpcBackendClient::CreateConnection()
{
    try
    {
        auto channel = CreateChannel();
        if (!channel)
        {
            LogError(L"Failed to create gRPC channel");
            return nullptr;
        }
        
        size_t connectionId = m_connectionIdCounter.fetch_add(1);
        auto connection = std::make_shared<PooledConnection>(channel, connectionId);
        
        LogDebug(L"Created new connection: %zu", connectionId);
        return connection;
    }
    catch (const std::exception& e)
    {
        LogError(L"Exception creating connection: %hs", e.what());
        return nullptr;
    }
}

std::shared_ptr<PooledConnection> GrpcBackendClient::GetConnection()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Try to get an available connection
    while (!m_availableConnections.empty())
    {
        auto connection = m_availableConnections.front();
        m_availableConnections.pop();
        
        if (connection && connection->IsHealthy())
        {
            LogDebug(L"Retrieved healthy connection: %zu", connection->GetId());
            return connection;
        }
        else
        {
            LogDebug(L"Removing unhealthy connection: %zu", 
                     connection ? connection->GetId() : 0);
            // Connection will be removed from m_allConnections during cleanup
        }
    }
    
    // Create new connection if under limit
    if (m_allConnections.size() < m_config.maxConnections)
    {
        auto connection = CreateConnection();
        if (connection)
        {
            m_allConnections.push_back(connection);
            return connection;
        }
    }
    
    LogWarning(L"No available connections");
    return nullptr;
}

void GrpcBackendClient::ReturnConnection(std::shared_ptr<PooledConnection> connection)
{
    if (!connection || !connection->IsHealthy())
    {
        LogDebug(L"Not returning unhealthy connection");
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    m_availableConnections.push(connection);
    LogDebug(L"Returned connection to pool: %zu", connection->GetId());
}

void GrpcBackendClient::RemoveConnection(std::shared_ptr<PooledConnection> connection)
{
    if (!connection)
    {
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto iter = std::find(m_allConnections.begin(), m_allConnections.end(), connection);
    if (iter != m_allConnections.end())
    {
        m_allConnections.erase(iter);
        LogDebug(L"Removed connection from pool: %zu", connection->GetId());
    }
}

std::shared_ptr<grpc::Channel> GrpcBackendClient::CreateChannel()
{
    try
    {
        auto credentials = SetupTlsCredentials();
        if (!credentials)
        {
            LogError(L"Failed to setup TLS credentials");
            return nullptr;
        }
        
        grpc::ChannelArguments args;
        args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, 30000);  // 30 seconds
        args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 5000); // 5 seconds
        args.SetInt(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);
        args.SetInt(GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA, 0);
        args.SetInt(GRPC_ARG_HTTP2_MIN_PING_INTERVAL_WITHOUT_DATA_MS, 300000);
        args.SetInt(GRPC_ARG_HTTP2_MIN_RECV_PING_INTERVAL_WITHOUT_DATA_MS, 300000);
        
        auto channel = grpc::CreateCustomChannel(m_config.endpoint, credentials, args);
        
        // Wait for connection to be ready (with timeout)
        auto deadline = std::chrono::system_clock::now() + m_config.connectionTimeout;
        if (channel->WaitForConnected(deadline))
        {
            LogDebug(L"Successfully created gRPC channel");
            return channel;
        }
        else
        {
            LogError(L"Failed to connect to gRPC server within timeout");
            return nullptr;
        }
    }
    catch (const std::exception& e)
    {
        LogError(L"Exception creating gRPC channel: %hs", e.what());
        return nullptr;
    }
}

std::shared_ptr<grpc::ChannelCredentials> GrpcBackendClient::SetupTlsCredentials()
{
    if (!m_config.enableTls)
    {
        LogInfo(L"TLS disabled, using insecure credentials");
        return grpc::InsecureChannelCredentials();
    }
    
    try
    {
        grpc::SslCredentialsOptions sslOpts;
        
        // Load CA certificate if provided
        if (!m_config.caCertificatePath.empty())
        {
            std::ifstream caFile(m_config.caCertificatePath);
            if (caFile.is_open())
            {
                std::string caCert((std::istreambuf_iterator<char>(caFile)),
                                  std::istreambuf_iterator<char>());
                sslOpts.pem_root_certs = caCert;
                LogDebug(L"Loaded CA certificate from: %hs", m_config.caCertificatePath.c_str());
            }
            else
            {
                LogWarning(L"Failed to load CA certificate from: %hs", 
                          m_config.caCertificatePath.c_str());
            }
        }
        
        // Load client certificate and key if provided
        if (!m_config.certificatePath.empty() && !m_config.privateKeyPath.empty())
        {
            std::ifstream certFile(m_config.certificatePath);
            std::ifstream keyFile(m_config.privateKeyPath);
            
            if (certFile.is_open() && keyFile.is_open())
            {
                std::string clientCert((std::istreambuf_iterator<char>(certFile)),
                                      std::istreambuf_iterator<char>());
                std::string clientKey((std::istreambuf_iterator<char>(keyFile)),
                                     std::istreambuf_iterator<char>());
                
                sslOpts.pem_cert_chain = clientCert;
                sslOpts.pem_private_key = clientKey;
                
                LogDebug(L"Loaded client certificate and key");
            }
            else
            {
                LogWarning(L"Failed to load client certificate or key");
            }
        }
        
        return grpc::SslCredentials(sslOpts);
    }
    catch (const std::exception& e)
    {
        LogError(L"Exception setting up TLS credentials: %hs", e.what());
        return grpc::InsecureChannelCredentials();
    }
}

// Circuit breaker methods

void GrpcBackendClient::OnSuccess()
{
    std::lock_guard<std::mutex> statsLock(m_statsMutex);
    m_stats.successfulRequests++;
    
    // Reset circuit breaker on success
    if (m_circuitBreakerState.load() == CircuitBreakerState::HalfOpen)
    {
        m_circuitBreakerState = CircuitBreakerState::Closed;
        m_failureCount = 0;
        m_halfOpenCallCount = 0;
        LogInfo(L"Circuit breaker closed after successful call");
    }
    else if (m_circuitBreakerState.load() == CircuitBreakerState::Closed)
    {
        m_failureCount = 0;
    }
}

void GrpcBackendClient::OnFailure()
{
    std::lock_guard<std::mutex> statsLock(m_statsMutex);
    m_stats.failedRequests++;
    
    size_t failures = m_failureCount.fetch_add(1) + 1;
    m_lastFailureTime = std::chrono::steady_clock::now();
    
    if (m_circuitBreakerState.load() == CircuitBreakerState::Closed)
    {
        if (failures >= m_config.failureThreshold)
        {
            m_circuitBreakerState = CircuitBreakerState::Open;
            LogWarning(L"Circuit breaker opened after %zu failures", failures);
        }
    }
}

bool GrpcBackendClient::ShouldAllowRequest()
{
    auto state = m_circuitBreakerState.load();
    
    if (state == CircuitBreakerState::Closed)
    {
        return true;
    }
    else if (state == CircuitBreakerState::Open)
    {
        auto now = std::chrono::steady_clock::now();
        auto timeSinceFailure = now - m_lastFailureTime;
        
        if (timeSinceFailure >= m_config.circuitBreakerTimeout)
        {
            // Try to move to half-open state
            CircuitBreakerState expected = CircuitBreakerState::Open;
            if (m_circuitBreakerState.compare_exchange_strong(expected, CircuitBreakerState::HalfOpen))
            {
                m_halfOpenCallCount = 0;
                LogInfo(L"Circuit breaker moved to half-open state");
            }
            return true;
        }
        return false;
    }
    else // HalfOpen
    {
        size_t calls = m_halfOpenCallCount.fetch_add(1);
        return calls < m_config.halfOpenMaxCalls;
    }
}

// Connection maintenance worker

void GrpcBackendClient::ConnectionMaintenanceWorker()
{
    LogDebug(L"Connection maintenance worker started");
    
    while (!m_shutdown)
    {
        try
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            
            // Wait for shutdown signal or maintenance interval
            if (m_maintenanceCondition.wait_for(lock, std::chrono::seconds(30), 
                [this] { return m_shutdown; }))
            {
                break; // Shutdown requested
            }
            
            if (!m_shutdown)
            {
                CleanupExpiredConnections();
            }
        }
        catch (const std::exception& e)
        {
            LogError(L"Exception in connection maintenance worker: %hs", e.what());
        }
    }
    
    LogDebug(L"Connection maintenance worker stopped");
}

void GrpcBackendClient::CleanupExpiredConnections()
{
    // This method is called with m_mutex locked
    
    auto now = std::chrono::steady_clock::now();
    auto maxAge = std::chrono::minutes(30); // Close connections older than 30 minutes
    
    auto iter = m_allConnections.begin();
    while (iter != m_allConnections.end())
    {
        auto connection = *iter;
        if (!connection || !connection->IsHealthy() || 
            (now - connection->GetCreatedAt()) > maxAge)
        {
            LogDebug(L"Removing expired/unhealthy connection: %zu", 
                     connection ? connection->GetId() : 0);
            iter = m_allConnections.erase(iter);
        }
        else
        {
            ++iter;
        }
    }
    
    // Clean up available connections queue
    std::queue<std::shared_ptr<PooledConnection>> cleanQueue;
    while (!m_availableConnections.empty())
    {
        auto connection = m_availableConnections.front();
        m_availableConnections.pop();
        
        if (connection && connection->IsHealthy() && 
            std::find(m_allConnections.begin(), m_allConnections.end(), connection) != m_allConnections.end())
        {
            cleanQueue.push(connection);
        }
    }
    m_availableConnections = cleanQueue;
    
    LogDebug(L"Connection cleanup completed. Active connections: %zu", m_allConnections.size());
}

// Template method implementations

template<typename T>
GrpcResult<T> GrpcBackendClient::ExecuteWithRetry(std::function<GrpcResult<T>()> operation)
{
    size_t attempts = 0;
    
    while (attempts < m_config.maxRetries)
    {
        auto result = operation();
        
        if (result.success || attempts == m_config.maxRetries - 1)
        {
            return result;
        }
        
        attempts++;
        LogDebug(L"Retrying operation, attempt %zu/%zu", attempts + 1, m_config.maxRetries);
        
        // Wait before retry
        std::this_thread::sleep_for(m_config.retryDelay);
    }
    
    return GrpcResult<T>("Max retries exceeded", static_cast<int>(KspErrorCode::BackendTimeout));
}

} // namespace ksp
} // namespace supacrypt