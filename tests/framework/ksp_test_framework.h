// ksp_test_framework.h - KSP Test Framework Header
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <windows.h>
#include <ncrypt.h>
#include <memory>
#include <vector>
#include <string>
#include <chrono>
#include <functional>

namespace supacrypt::ksp::test {

// Forward declarations
class KspPerformanceProfiler;
class KspSecurityValidator;
class KspWindowsUtils;

// Test configuration constants
constexpr DWORD KSP_TEST_TIMEOUT_MS = 30000;
constexpr DWORD KSP_PERFORMANCE_ITERATIONS = 1000;
constexpr DWORD KSP_LOAD_TEST_CONCURRENT_OPERATIONS = 100;
constexpr size_t KSP_MAX_TEST_DATA_SIZE = 1024 * 1024; // 1MB

// KSP Performance targets from Task 4.3
constexpr DWORD KSP_INIT_TARGET_MS = 100;
constexpr DWORD KSP_RSA2048_SIGN_TARGET_MS = 100;
constexpr DWORD KSP_ECC_P256_SIGN_TARGET_MS = 50;
constexpr DWORD KSP_KEY_ENUM_TARGET_MS = 200;

// Performance metrics structure
struct KspPerformanceMetrics {
    std::chrono::milliseconds initTime;
    std::chrono::milliseconds operationTime;
    std::chrono::milliseconds cleanupTime;
    size_t memoryUsage;
    DWORD handleCount;
    bool success;
    std::string operationName;
};

// Security test results
struct KspSecurityTestResult {
    bool accessControlValid;
    bool keyIsolationValid;
    bool noMemoryLeaks;
    bool noHandleLeaks;
    bool noInformationLeakage;
    std::vector<std::string> vulnerabilities;
};

// Algorithm test parameters
struct KspAlgorithmTestParams {
    std::wstring name;
    DWORD keySize;
    bool supportsEncryption;
    bool supportsSignature;
    bool supportsKeyAgreement;
};

// Base test fixture for KSP testing
class KspTestBase : public ::testing::Test {
public:
    KspTestBase();
    virtual ~KspTestBase();

protected:
    void SetUp() override;
    void TearDown() override;

    // KSP provider management
    NTSTATUS OpenKspProvider(NCRYPT_PROV_HANDLE* phProvider, DWORD dwFlags = 0);
    NTSTATUS CloseKspProvider(NCRYPT_PROV_HANDLE hProvider);
    std::wstring GetKspProviderName() const;

    // Key management
    NTSTATUS CreateKspKey(NCRYPT_PROV_HANDLE hProvider, 
                         NCRYPT_KEY_HANDLE* phKey,
                         LPCWSTR pszAlgId,
                         LPCWSTR pszKeyName = nullptr,
                         DWORD dwFlags = 0);
    NTSTATUS OpenKspKey(NCRYPT_PROV_HANDLE hProvider,
                       NCRYPT_KEY_HANDLE* phKey,
                       LPCWSTR pszKeyName,
                       DWORD dwFlags = 0);
    NTSTATUS FinalizeKspKey(NCRYPT_KEY_HANDLE hKey, DWORD dwFlags = 0);
    NTSTATUS DeleteKspKey(NCRYPT_KEY_HANDLE hKey, DWORD dwFlags = 0);

    // Key properties
    NTSTATUS GetKspKeyProperty(NCRYPT_KEY_HANDLE hKey,
                              LPCWSTR pszProperty,
                              PBYTE pbOutput,
                              DWORD cbOutput,
                              DWORD* pcbResult,
                              DWORD dwFlags = 0);
    NTSTATUS SetKspKeyProperty(NCRYPT_KEY_HANDLE hKey,
                              LPCWSTR pszProperty,
                              PBYTE pbInput,
                              DWORD cbInput,
                              DWORD dwFlags = 0);

    // Cryptographic operations
    NTSTATUS SignData(NCRYPT_KEY_HANDLE hKey, 
                     const std::vector<BYTE>& data, 
                     std::vector<BYTE>& signature);
    NTSTATUS VerifySignature(NCRYPT_KEY_HANDLE hKey, 
                           const std::vector<BYTE>& data, 
                           const std::vector<BYTE>& signature);
    NTSTATUS EncryptData(NCRYPT_KEY_HANDLE hKey, 
                        const std::vector<BYTE>& plaintext, 
                        std::vector<BYTE>& ciphertext);
    NTSTATUS DecryptData(NCRYPT_KEY_HANDLE hKey, 
                        const std::vector<BYTE>& ciphertext, 
                        std::vector<BYTE>& plaintext);

    // Key enumeration
    NTSTATUS EnumerateKeys(NCRYPT_PROV_HANDLE hProvider, 
                          std::vector<std::wstring>& keyNames);

    // Test utilities
    std::vector<BYTE> GenerateRandomData(size_t size);
    std::wstring GenerateRandomKeyName();
    void ValidateNTStatus(NTSTATUS result, NTSTATUS expected);
    void ValidateSecurityContext();

    // Performance measurement
    KspPerformanceMetrics MeasureOperation(std::function<NTSTATUS()> operation, const std::string& name = "");
    void ValidatePerformanceTarget(const KspPerformanceMetrics& metrics, std::chrono::milliseconds maxTime);

    // Resource tracking
    void StartResourceTracking();
    void StopResourceTracking();
    bool ValidateNoResourceLeaks();

    // Test data and utilities
    std::vector<KspAlgorithmTestParams> supportedAlgorithms_;
    std::unique_ptr<KspPerformanceProfiler> profiler_;
    std::unique_ptr<KspSecurityValidator> validator_;
    std::unique_ptr<KspWindowsUtils> utils_;

private:
    NCRYPT_PROV_HANDLE defaultProvider_;
    size_t initialMemoryUsage_;
    DWORD initialHandleCount_;
    bool resourceTrackingActive_;
};

// Enhanced KSP test fixture with additional validation
class KspEnhancedTest : public KspTestBase {
protected:
    void SetUp() override;
    void TearDown() override;

    // Enhanced validation methods
    void ValidateProviderCapabilities(NCRYPT_PROV_HANDLE hProvider);
    void ValidateAlgorithmSupport(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszAlgId);
    void ValidateKeyProperties(NCRYPT_KEY_HANDLE hKey);
    void ValidateErrorHandling();

    // Concurrency testing utilities
    void RunConcurrentOperations(DWORD numThreads, DWORD operationsPerThread);
    void RunMemoryStressTest();
    void RunHandleStressTest();
};

// Performance test fixture
class KspPerformanceTest : public KspEnhancedTest {
protected:
    void SetUp() override;

    // Benchmark methods
    KspPerformanceMetrics BenchmarkInitialization(DWORD iterations = KSP_PERFORMANCE_ITERATIONS);
    KspPerformanceMetrics BenchmarkKeyGeneration(LPCWSTR pszAlgId, DWORD iterations = 100);
    KspPerformanceMetrics BenchmarkSignature(LPCWSTR pszAlgId, size_t dataSize, DWORD iterations = KSP_PERFORMANCE_ITERATIONS);
    KspPerformanceMetrics BenchmarkEncryption(LPCWSTR pszAlgId, size_t dataSize, DWORD iterations = KSP_PERFORMANCE_ITERATIONS);
    KspPerformanceMetrics BenchmarkKeyEnumeration(DWORD numKeys, DWORD iterations = 10);

    // Load testing
    KspPerformanceMetrics LoadTest(DWORD concurrentOperations = KSP_LOAD_TEST_CONCURRENT_OPERATIONS);
    KspPerformanceMetrics StressTest(DWORD durationMinutes = 5);

    // Report generation
    void GeneratePerformanceReport(const std::string& filename);

private:
    std::vector<KspPerformanceMetrics> metrics_;
};

// Security test fixture
class KspSecurityTest : public KspEnhancedTest {
protected:
    void SetUp() override;

    // Security validation methods
    KspSecurityTestResult ValidateAccessControl();
    KspSecurityTestResult ValidateKeyIsolation();
    KspSecurityTestResult ValidateMemorySecurity();
    KspSecurityTestResult ValidateHandleSecurity();
    KspSecurityTestResult ValidateErrorHandling();

    // Attack simulation
    KspSecurityTestResult SimulateHandleHijacking();
    KspSecurityTestResult SimulatePrivilegeEscalation();
    KspSecurityTestResult SimulateInformationLeakage();

    // Report generation
    void GenerateSecurityReport(const std::string& filename);

private:
    std::vector<KspSecurityTestResult> results_;
};

// Integration test fixture
class KspIntegrationTest : public KspEnhancedTest {
protected:
    void SetUp() override;
    void TearDown() override;

    // Windows API integration
    bool TestCertificateEnrollment();
    bool TestCertificateManagerIntegration();
    bool TestEventLogIntegration();
    bool TestRegistryIntegration();

    // Application compatibility
    bool TestDotNetIntegration();
    bool TestWindowsSecurityIntegration();
    bool TestCNGAPICompatibility();

private:
    HCERTSTORE testCertStore_;
};

// Architecture test fixture
class KspArchitectureTest : public KspEnhancedTest {
protected:
    // Architecture-specific tests
    bool TestX86Compatibility();
    bool TestX64Optimization();
    bool TestARM64Support();
    bool TestWOW64Compatibility();
    bool TestDataStructureAlignment();

    // Cross-platform validation
    void ValidateArchitectureSpecificBehavior();
    void ValidatePointerSizeCompatibility();
    void ValidateCallingConventions();
};

// Test macros for enhanced functionality
#define EXPECT_KSP_SUCCESS(status) \
    EXPECT_EQ(status, STATUS_SUCCESS) << "KSP operation failed with NTSTATUS: 0x" << std::hex << status

#define EXPECT_KSP_ERROR(actual, expected) \
    EXPECT_EQ(actual, expected) << "Expected NTSTATUS: 0x" << std::hex << expected << ", Got: 0x" << std::hex << actual

#define EXPECT_PERFORMANCE_TARGET_KSP(metrics, maxTime) \
    EXPECT_LE(metrics.operationTime.count(), maxTime.count()) << \
    "KSP operation '" << metrics.operationName << "' took " << metrics.operationTime.count() << \
    "ms, expected <= " << maxTime.count() << "ms"

#define EXPECT_NO_RESOURCE_LEAKS_KSP() \
    EXPECT_TRUE(ValidateNoResourceLeaks()) << "KSP resource leaks detected"

// Parameterized test helpers
std::vector<KspAlgorithmTestParams> GetSupportedKspAlgorithms();
std::vector<std::wstring> GetTestKspKeyNames();
std::vector<size_t> GetTestDataSizes();
std::vector<DWORD> GetKspTestFlags();

} // namespace supacrypt::ksp::test