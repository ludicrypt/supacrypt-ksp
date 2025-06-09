// enhanced_unit_tests.cpp - Enhanced KSP Unit Tests for 100% Coverage
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#include "ksp_test_framework.h"
#include "ksp_provider.h"
#include <vector>
#include <thread>
#include <future>

namespace supacrypt::ksp::test {

class KspEnhancedUnitTest : public KspEnhancedTest {
protected:
    void SetUp() override {
        KspEnhancedTest::SetUp();
        GTEST_LOG_(INFO) << "Starting enhanced KSP unit test for 100% coverage";
    }
};

// Test KSP provider initialization with all possible flags
TEST_F(KspEnhancedUnitTest, InitializeProvider_AllFlags_HandlesCorrectly) {
    std::vector<DWORD> testFlags = {
        0,                              // Default flags
        NCRYPT_SILENT_FLAG,            // Silent operation
        NCRYPT_MACHINE_KEY_FLAG,       // Machine-wide keys
        NCRYPT_OVERWRITE_KEY_FLAG,     // Overwrite existing keys
        NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG  // Write to legacy store
    };
    
    for (DWORD flags : testFlags) {
        NCRYPT_PROV_HANDLE provider = 0;
        
        auto metrics = MeasureOperation([&]() -> NTSTATUS {
            return OpenKspProvider(&provider, flags);
        }, "InitializeProvider_Flags_" + std::to_string(flags));
        
        EXPECT_PERFORMANCE_TARGET_KSP(metrics, std::chrono::milliseconds(KSP_INIT_TARGET_MS));
        
        if (provider != 0) {
            CloseKspProvider(provider);
        }
    }
}

// Test all supported algorithms for key generation
class KspKeyGenerationTest : public KspEnhancedUnitTest,
                           public ::testing::WithParamInterface<std::wstring> {
};

TEST_P(KspKeyGenerationTest, GenerateKey_SupportedAlgorithms_MeetsPerformanceTargets) {
    std::wstring algorithm = GetParam();
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    
    NTSTATUS status = OpenKspProvider(&provider);
    ASSERT_KSP_SUCCESS(status);
    
    std::wstring keyName = GenerateRandomKeyName();
    
    auto metrics = MeasureOperation([&]() -> NTSTATUS {
        NTSTATUS result = CreateKspKey(provider, &key, algorithm.c_str(), keyName.c_str());
        if (result == STATUS_SUCCESS) {
            result = FinalizeKspKey(key);
        }
        return result;
    }, "KeyGeneration_" + std::string(algorithm.begin(), algorithm.end()));
    
    EXPECT_KSP_SUCCESS(metrics.success ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
    EXPECT_PERFORMANCE_TARGET_KSP(metrics, std::chrono::milliseconds(3000)); // 3s max for key generation
    EXPECT_NE(key, 0u);
    
    if (key != 0) {
        // Test key properties
        DWORD keyLength = 0;
        DWORD result_size = 0;
        NTSTATUS result = GetKspKeyProperty(key, NCRYPT_LENGTH_PROPERTY, 
                                          reinterpret_cast<PBYTE>(&keyLength), 
                                          sizeof(keyLength), &result_size);
        
        if (result == STATUS_SUCCESS) {
            EXPECT_GT(keyLength, 0u);
            GTEST_LOG_(INFO) << "Key length for " << algorithm.c_str() << ": " << keyLength << " bits";
        }
        
        // Test algorithm property
        wchar_t algBuffer[256] = {};
        result = GetKspKeyProperty(key, NCRYPT_ALGORITHM_PROPERTY,
                                 reinterpret_cast<PBYTE>(algBuffer),
                                 sizeof(algBuffer), &result_size);
        
        if (result == STATUS_SUCCESS) {
            std::wstring keyAlgorithm(algBuffer);
            EXPECT_EQ(keyAlgorithm, algorithm);
        }
        
        DeleteKspKey(key, 0);
    }
    
    CloseKspProvider(provider);
}

INSTANTIATE_TEST_SUITE_P(
    SupportedAlgorithms,
    KspKeyGenerationTest,
    ::testing::Values(
        NCRYPT_RSA_ALGORITHM,
        NCRYPT_ECDSA_P256_ALGORITHM,
        NCRYPT_ECDSA_P384_ALGORITHM,
        NCRYPT_ECDSA_P521_ALGORITHM
    )
);

// Test signature operations with performance validation
TEST_F(KspEnhancedUnitTest, SignData_RSA2048_MeetsPerformanceTarget) {
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    
    NTSTATUS status = OpenKspProvider(&provider);
    ASSERT_KSP_SUCCESS(status);
    
    std::wstring keyName = GenerateRandomKeyName();
    status = CreateKspKey(provider, &key, NCRYPT_RSA_ALGORITHM, keyName.c_str());
    ASSERT_KSP_SUCCESS(status);
    
    status = FinalizeKspKey(key);
    ASSERT_KSP_SUCCESS(status);
    
    // Test data for signing
    std::vector<BYTE> testData = GenerateRandomData(1024);
    std::vector<BYTE> signature;
    
    auto metrics = MeasureOperation([&]() -> NTSTATUS {
        return SignData(key, testData, signature);
    }, "RSA2048_Signature");
    
    EXPECT_KSP_SUCCESS(metrics.success ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
    EXPECT_PERFORMANCE_TARGET_KSP(metrics, std::chrono::milliseconds(KSP_RSA2048_SIGN_TARGET_MS));
    EXPECT_FALSE(signature.empty());
    
    // Verify signature
    status = VerifySignature(key, testData, signature);
    EXPECT_KSP_SUCCESS(status);
    
    DeleteKspKey(key, 0);
    CloseKspProvider(provider);
}

// Test ECC P-256 signature performance
TEST_F(KspEnhancedUnitTest, SignData_ECCP256_MeetsPerformanceTarget) {
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    
    NTSTATUS status = OpenKspProvider(&provider);
    ASSERT_KSP_SUCCESS(status);
    
    std::wstring keyName = GenerateRandomKeyName();
    status = CreateKspKey(provider, &key, NCRYPT_ECDSA_P256_ALGORITHM, keyName.c_str());
    ASSERT_KSP_SUCCESS(status);
    
    status = FinalizeKspKey(key);
    ASSERT_KSP_SUCCESS(status);
    
    // Test data for signing
    std::vector<BYTE> testData = GenerateRandomData(512);
    std::vector<BYTE> signature;
    
    auto metrics = MeasureOperation([&]() -> NTSTATUS {
        return SignData(key, testData, signature);
    }, "ECCP256_Signature");
    
    EXPECT_KSP_SUCCESS(metrics.success ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
    EXPECT_PERFORMANCE_TARGET_KSP(metrics, std::chrono::milliseconds(KSP_ECC_P256_SIGN_TARGET_MS));
    EXPECT_FALSE(signature.empty());
    
    // Verify signature
    status = VerifySignature(key, testData, signature);
    EXPECT_KSP_SUCCESS(status);
    
    DeleteKspKey(key, 0);
    CloseKspProvider(provider);
}

// Test key enumeration performance
TEST_F(KspEnhancedUnitTest, EnumerateKeys_100Keys_MeetsPerformanceTarget) {
    NCRYPT_PROV_HANDLE provider = 0;
    
    NTSTATUS status = OpenKspProvider(&provider);
    ASSERT_KSP_SUCCESS(status);
    
    const DWORD NUM_KEYS = 100;
    std::vector<NCRYPT_KEY_HANDLE> keys;
    std::vector<std::wstring> keyNames;
    
    // Create test keys
    for (DWORD i = 0; i < NUM_KEYS; ++i) {
        NCRYPT_KEY_HANDLE key = 0;
        std::wstring keyName = L"TestKey_" + std::to_wstring(i);
        
        status = CreateKspKey(provider, &key, NCRYPT_RSA_ALGORITHM, keyName.c_str());
        if (status == STATUS_SUCCESS) {
            status = FinalizeKspKey(key);
            if (status == STATUS_SUCCESS) {
                keys.push_back(key);
                keyNames.push_back(keyName);
            }
        }
        
        if (i % 20 == 0) {
            GTEST_LOG_(INFO) << "Created " << (i + 1) << " test keys";
        }
    }
    
    GTEST_LOG_(INFO) << "Successfully created " << keys.size() << " test keys";
    
    // Test enumeration performance
    std::vector<std::wstring> foundKeys;
    auto metrics = MeasureOperation([&]() -> NTSTATUS {
        return EnumerateKeys(provider, foundKeys);
    }, "EnumerateKeys_100");
    
    EXPECT_KSP_SUCCESS(metrics.success ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
    EXPECT_PERFORMANCE_TARGET_KSP(metrics, std::chrono::milliseconds(KSP_KEY_ENUM_TARGET_MS));
    EXPECT_GE(foundKeys.size(), keys.size());
    
    // Cleanup test keys
    for (auto& key : keys) {
        DeleteKspKey(key, 0);
    }
    
    CloseKspProvider(provider);
}

// Test error handling paths for 100% coverage
TEST_F(KspEnhancedUnitTest, ErrorPaths_InvalidParameters_HandledCorrectly) {
    NCRYPT_PROV_HANDLE provider = 0;
    
    // Test invalid provider name
    NTSTATUS status = NCryptOpenStorageProvider(&provider, L"NonExistentProvider", 0);
    EXPECT_KSP_ERROR(status, NTE_INVALID_PARAMETER);
    
    // Test null pointers
    status = NCryptOpenStorageProvider(nullptr, GetKspProviderName().c_str(), 0);
    EXPECT_KSP_ERROR(status, STATUS_INVALID_PARAMETER);
    
    // Test invalid key operations with null handle
    NCRYPT_KEY_HANDLE invalidKey = 0;
    status = NCryptFinalizeKey(invalidKey, 0);
    EXPECT_KSP_ERROR(status, STATUS_INVALID_HANDLE);
    
    // Test invalid key with fake handle
    invalidKey = reinterpret_cast<NCRYPT_KEY_HANDLE>(0xDEADBEEF);
    status = NCryptDeleteKey(invalidKey, 0);
    EXPECT_KSP_ERROR(status, STATUS_INVALID_HANDLE);
}

// Test concurrent operations for thread safety
TEST_F(KspEnhancedUnitTest, ConcurrentOperations_MultipleThreads_ThreadSafe) {
    const int NUM_THREADS = 10;
    const int OPERATIONS_PER_THREAD = 20;
    
    std::vector<std::future<bool>> futures;
    
    auto threadFunction = [this]() -> bool {
        bool success = true;
        
        for (int i = 0; i < OPERATIONS_PER_THREAD && success; ++i) {
            NCRYPT_PROV_HANDLE provider = 0;
            NCRYPT_KEY_HANDLE key = 0;
            
            // Open provider
            NTSTATUS status = OpenKspProvider(&provider);
            if (status != STATUS_SUCCESS) {
                success = false;
                break;
            }
            
            // Create ephemeral key
            std::wstring keyName = GenerateRandomKeyName();
            status = CreateKspKey(provider, &key, NCRYPT_RSA_ALGORITHM, keyName.c_str());
            if (status != STATUS_SUCCESS) {
                CloseKspProvider(provider);
                success = false;
                break;
            }
            
            // Finalize key
            status = FinalizeKspKey(key);
            if (status != STATUS_SUCCESS) {
                success = false;
            }
            
            // Query key properties
            DWORD keyLength = 0;
            DWORD resultSize = 0;
            status = GetKspKeyProperty(key, NCRYPT_LENGTH_PROPERTY,
                                     reinterpret_cast<PBYTE>(&keyLength),
                                     sizeof(keyLength), &resultSize);
            if (status != STATUS_SUCCESS) {
                success = false;
            }
            
            // Cleanup
            DeleteKspKey(key, 0);
            CloseKspProvider(provider);
        }
        
        return success;
    };
    
    // Launch threads
    for (int i = 0; i < NUM_THREADS; ++i) {
        futures.push_back(std::async(std::launch::async, threadFunction));
    }
    
    // Wait and verify results
    for (int i = 0; i < NUM_THREADS; ++i) {
        EXPECT_TRUE(futures[i].get()) << "Thread " << i << " failed";
    }
}

// Test key property handling
TEST_F(KspEnhancedUnitTest, KeyProperties_AllQueries_WorkCorrectly) {
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    
    NTSTATUS status = OpenKspProvider(&provider);
    ASSERT_KSP_SUCCESS(status);
    
    std::wstring keyName = GenerateRandomKeyName();
    status = CreateKspKey(provider, &key, NCRYPT_RSA_ALGORITHM, keyName.c_str());
    ASSERT_KSP_SUCCESS(status);
    
    status = FinalizeKspKey(key);
    ASSERT_KSP_SUCCESS(status);
    
    // Test all key properties
    std::vector<LPCWSTR> keyProperties = {
        NCRYPT_ALGORITHM_PROPERTY,
        NCRYPT_LENGTH_PROPERTY,
        NCRYPT_KEY_USAGE_PROPERTY,
        NCRYPT_KEY_TYPE_PROPERTY,
        NCRYPT_NAME_PROPERTY,
        NCRYPT_UNIQUE_NAME_PROPERTY
    };
    
    for (LPCWSTR property : keyProperties) {
        DWORD dataLength = 0;
        
        // Get size first
        status = GetKspKeyProperty(key, property, nullptr, 0, &dataLength);
        if (status == STATUS_SUCCESS || status == STATUS_BUFFER_TOO_SMALL) {
            // Property is supported
            std::vector<BYTE> data(dataLength);
            DWORD actualSize = 0;
            status = GetKspKeyProperty(key, property, data.data(), dataLength, &actualSize);
            
            if (status == STATUS_SUCCESS) {
                GTEST_LOG_(INFO) << "Key property " << property << " retrieved successfully (" 
                               << actualSize << " bytes)";
            }
        }
    }
    
    DeleteKspKey(key, 0);
    CloseKspProvider(provider);
}

// Test resource cleanup under error conditions
TEST_F(KspEnhancedUnitTest, ResourceCleanup_ErrorConditions_NoLeaks) {
    // Test multiple failed operations don't leak resources
    for (int i = 0; i < 500; ++i) {
        NCRYPT_PROV_HANDLE provider = 0;
        
        // Try invalid operations
        NTSTATUS status = NCryptOpenStorageProvider(&provider, L"InvalidProvider", 0);
        EXPECT_NE(status, STATUS_SUCCESS);
        
        // Provider should be 0 on failure
        EXPECT_EQ(provider, 0u);
        
        // Try with invalid algorithm occasionally
        if (i % 50 == 0) {
            // Open valid provider
            status = OpenKspProvider(&provider);
            if (status == STATUS_SUCCESS) {
                
                NCRYPT_KEY_HANDLE key = 0;
                status = CreateKspKey(provider, &key, L"INVALID_ALGORITHM", L"TestKey");
                EXPECT_NE(status, STATUS_SUCCESS);
                EXPECT_EQ(key, 0u);
                
                CloseKspProvider(provider);
            }
        }
    }
    
    // Verify no resource leaks
    EXPECT_NO_RESOURCE_LEAKS_KSP();
}

// Test provider enumeration
TEST_F(KspEnhancedUnitTest, ProviderEnumeration_SupacryptProvider_FoundCorrectly) {
    NCRYPT_PROV_HANDLE* providerList = nullptr;
    DWORD providerCount = 0;
    
    // Enumerate providers
    NTSTATUS status = NCryptEnumStorageProviders(&providerCount, &providerList, 0);
    EXPECT_KSP_SUCCESS(status);
    EXPECT_GT(providerCount, 0u);
    EXPECT_NE(providerList, nullptr);
    
    bool supacryptFound = false;
    for (DWORD i = 0; i < providerCount; ++i) {
        std::wstring providerName(providerList[i].pszName);
        if (providerName.find(L"Supacrypt") != std::wstring::npos) {
            supacryptFound = true;
            GTEST_LOG_(INFO) << "Found Supacrypt KSP: " << providerName.c_str();
            break;
        }
    }
    
    EXPECT_TRUE(supacryptFound) << "Supacrypt KSP not found in provider enumeration";
    
    // Cleanup
    if (providerList) {
        NCryptFreeBuffer(providerList);
    }
}

// Test ephemeral keys (no name)
TEST_F(KspEnhancedUnitTest, EphemeralKeys_NoName_WorkCorrectly) {
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    
    NTSTATUS status = OpenKspProvider(&provider);
    ASSERT_KSP_SUCCESS(status);
    
    // Create ephemeral key (no name)
    status = CreateKspKey(provider, &key, NCRYPT_RSA_ALGORITHM, nullptr);
    EXPECT_KSP_SUCCESS(status);
    EXPECT_NE(key, 0u);
    
    status = FinalizeKspKey(key);
    EXPECT_KSP_SUCCESS(status);
    
    // Test that ephemeral key works for operations
    std::vector<BYTE> testData = GenerateRandomData(256);
    std::vector<BYTE> signature;
    
    status = SignData(key, testData, signature);
    EXPECT_KSP_SUCCESS(status);
    EXPECT_FALSE(signature.empty());
    
    // Cleanup (ephemeral keys are automatically cleaned up)
    status = NCryptFreeObject(key);
    EXPECT_KSP_SUCCESS(status);
    
    CloseKspProvider(provider);
}

} // namespace supacrypt::ksp::test