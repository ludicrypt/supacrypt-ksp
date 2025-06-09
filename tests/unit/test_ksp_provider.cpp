// test_ksp_provider.cpp - Unit tests for KSP provider
// Copyright (c) 2025 ludicrypt. All rights reserved.
// Licensed under the MIT License.

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <windows.h>
#include <ncrypt.h>

#include "ksp_provider.h"
#include "error_handling.h"
#include "test_config.h"

using namespace supacrypt::ksp;
using namespace testing;

class KspProviderTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Initialize error handling
        ASSERT_TRUE(InitializeErrorHandling());
        
        // Get provider instance
        provider_ = &WindowsKspProvider::GetInstance();
        ASSERT_NE(provider_, nullptr);
        
        // Initialize provider
        NTSTATUS status = provider_->Initialize();
        ASSERT_EQ(status, STATUS_SUCCESS);
    }
    
    void TearDown() override
    {
        if (provider_)
        {
            provider_->Shutdown();
        }
        
        ShutdownErrorHandling();
    }
    
    WindowsKspProvider* provider_ = nullptr;
};

TEST_F(KspProviderTest, GetInterface_ValidInterface_ReturnsSuccess)
{
    NCRYPT_INTERFACE_FN_TABLE* functionTable = nullptr;
    
    NTSTATUS status = provider_->GetInterface(
        NCRYPT_KEY_STORAGE_INTERFACE,
        &functionTable,
        0);
    
    EXPECT_EQ(status, STATUS_SUCCESS);
    EXPECT_NE(functionTable, nullptr);
}

TEST_F(KspProviderTest, GetInterface_InvalidInterface_ReturnsNotSupported)
{
    NCRYPT_INTERFACE_FN_TABLE* functionTable = nullptr;
    
    NTSTATUS status = provider_->GetInterface(
        L"INVALID_INTERFACE",
        &functionTable,
        0);
    
    EXPECT_EQ(status, STATUS_NOT_SUPPORTED);
    EXPECT_EQ(functionTable, nullptr);
}

TEST_F(KspProviderTest, GetInterface_NullPointer_ReturnsInvalidParameter)
{
    NTSTATUS status = provider_->GetInterface(
        NCRYPT_KEY_STORAGE_INTERFACE,
        nullptr,
        0);
    
    EXPECT_EQ(status, STATUS_INVALID_PARAMETER);
}

TEST_F(KspProviderTest, OpenProvider_ValidCall_ReturnsSuccess)
{
    NCRYPT_PROV_HANDLE providerHandle = 0;
    
    NTSTATUS status = provider_->OpenProvider(
        &providerHandle,
        L"Supacrypt Key Storage Provider",
        0);
    
    EXPECT_EQ(status, STATUS_SUCCESS);
    EXPECT_NE(providerHandle, 0);
    
    // Clean up
    provider_->CloseProvider(providerHandle, 0);
}

TEST_F(KspProviderTest, OpenProvider_NullName_ReturnsSuccess)
{
    NCRYPT_PROV_HANDLE providerHandle = 0;
    
    NTSTATUS status = provider_->OpenProvider(
        &providerHandle,
        nullptr,  // NULL provider name should be accepted
        0);
    
    EXPECT_EQ(status, STATUS_SUCCESS);
    EXPECT_NE(providerHandle, 0);
    
    // Clean up
    provider_->CloseProvider(providerHandle, 0);
}

TEST_F(KspProviderTest, OpenProvider_InvalidName_ReturnsNotFound)
{
    NCRYPT_PROV_HANDLE providerHandle = 0;
    
    NTSTATUS status = provider_->OpenProvider(
        &providerHandle,
        L"Invalid Provider Name",
        0);
    
    EXPECT_EQ(status, STATUS_NOT_FOUND);
    EXPECT_EQ(providerHandle, 0);
}

TEST_F(KspProviderTest, OpenProvider_NullHandle_ReturnsInvalidParameter)
{
    NTSTATUS status = provider_->OpenProvider(
        nullptr,
        L"Supacrypt Key Storage Provider",
        0);
    
    EXPECT_EQ(status, STATUS_INVALID_PARAMETER);
}

TEST_F(KspProviderTest, CloseProvider_ValidHandle_ReturnsSuccess)
{
    NCRYPT_PROV_HANDLE providerHandle = 0;
    
    // Open provider first
    NTSTATUS status = provider_->OpenProvider(&providerHandle, nullptr, 0);
    ASSERT_EQ(status, STATUS_SUCCESS);
    
    // Close provider
    status = provider_->CloseProvider(providerHandle, 0);
    EXPECT_EQ(status, STATUS_SUCCESS);
}

TEST_F(KspProviderTest, CloseProvider_InvalidHandle_ReturnsInvalidHandle)
{
    NCRYPT_PROV_HANDLE invalidHandle = 0xDEADBEEF;
    
    NTSTATUS status = provider_->CloseProvider(invalidHandle, 0);
    EXPECT_EQ(status, STATUS_INVALID_HANDLE);
}

TEST_F(KspProviderTest, CreateKey_ValidParameters_ReturnsSuccess)
{
    NCRYPT_PROV_HANDLE providerHandle = 0;
    NCRYPT_KEY_HANDLE keyHandle = 0;
    
    // Open provider first
    NTSTATUS status = provider_->OpenProvider(&providerHandle, nullptr, 0);
    ASSERT_EQ(status, STATUS_SUCCESS);
    
    // Create key
    status = provider_->CreateKey(
        providerHandle,
        &keyHandle,
        NCRYPT_RSA_ALGORITHM,
        L"TestKey",
        0,
        0);
    
    EXPECT_EQ(status, STATUS_SUCCESS);
    EXPECT_NE(keyHandle, 0);
    
    // Clean up
    if (keyHandle != 0)
    {
        provider_->DeleteKey(keyHandle, 0);
    }
    provider_->CloseProvider(providerHandle, 0);
}

TEST_F(KspProviderTest, CreateKey_EphemeralKey_ReturnsSuccess)
{
    NCRYPT_PROV_HANDLE providerHandle = 0;
    NCRYPT_KEY_HANDLE keyHandle = 0;
    
    // Open provider first
    NTSTATUS status = provider_->OpenProvider(&providerHandle, nullptr, 0);
    ASSERT_EQ(status, STATUS_SUCCESS);
    
    // Create ephemeral key (no name)
    status = provider_->CreateKey(
        providerHandle,
        &keyHandle,
        NCRYPT_RSA_ALGORITHM,
        nullptr,  // Ephemeral key
        0,
        0);
    
    EXPECT_EQ(status, STATUS_SUCCESS);
    EXPECT_NE(keyHandle, 0);
    
    // Clean up
    if (keyHandle != 0)
    {
        provider_->DeleteKey(keyHandle, 0);
    }
    provider_->CloseProvider(providerHandle, 0);
}

TEST_F(KspProviderTest, CreateKey_InvalidProvider_ReturnsInvalidHandle)
{
    NCRYPT_PROV_HANDLE invalidProvider = 0xDEADBEEF;
    NCRYPT_KEY_HANDLE keyHandle = 0;
    
    NTSTATUS status = provider_->CreateKey(
        invalidProvider,
        &keyHandle,
        NCRYPT_RSA_ALGORITHM,
        L"TestKey",
        0,
        0);
    
    EXPECT_EQ(status, STATUS_INVALID_HANDLE);
    EXPECT_EQ(keyHandle, 0);
}

TEST_F(KspProviderTest, CreateKey_NullKeyHandle_ReturnsInvalidParameter)
{
    NCRYPT_PROV_HANDLE providerHandle = 0;
    
    // Open provider first
    NTSTATUS status = provider_->OpenProvider(&providerHandle, nullptr, 0);
    ASSERT_EQ(status, STATUS_SUCCESS);
    
    // Try to create key with null handle pointer
    status = provider_->CreateKey(
        providerHandle,
        nullptr,  // Invalid
        NCRYPT_RSA_ALGORITHM,
        L"TestKey",
        0,
        0);
    
    EXPECT_EQ(status, STATUS_INVALID_PARAMETER);
    
    // Clean up
    provider_->CloseProvider(providerHandle, 0);
}

TEST_F(KspProviderTest, CreateKey_UnsupportedAlgorithm_ReturnsNotSupported)
{
    NCRYPT_PROV_HANDLE providerHandle = 0;
    NCRYPT_KEY_HANDLE keyHandle = 0;
    
    // Open provider first
    NTSTATUS status = provider_->OpenProvider(&providerHandle, nullptr, 0);
    ASSERT_EQ(status, STATUS_SUCCESS);
    
    // Try to create key with unsupported algorithm
    status = provider_->CreateKey(
        providerHandle,
        &keyHandle,
        L"UNSUPPORTED_ALGORITHM",
        L"TestKey",
        0,
        0);
    
    // Should fail during key storage or algorithm validation
    EXPECT_NE(status, STATUS_SUCCESS);
    EXPECT_EQ(keyHandle, 0);
    
    // Clean up
    provider_->CloseProvider(providerHandle, 0);
}

TEST_F(KspProviderTest, FinalizeKey_ValidKey_ReturnsSuccess)
{
    NCRYPT_PROV_HANDLE providerHandle = 0;
    NCRYPT_KEY_HANDLE keyHandle = 0;
    
    // Open provider and create key
    NTSTATUS status = provider_->OpenProvider(&providerHandle, nullptr, 0);
    ASSERT_EQ(status, STATUS_SUCCESS);
    
    status = provider_->CreateKey(
        providerHandle,
        &keyHandle,
        NCRYPT_RSA_ALGORITHM,
        L"TestKey",
        0,
        0);
    ASSERT_EQ(status, STATUS_SUCCESS);
    
    // Finalize key
    status = provider_->FinalizeKey(keyHandle, 0);
    EXPECT_EQ(status, STATUS_SUCCESS);
    
    // Clean up
    provider_->DeleteKey(keyHandle, 0);
    provider_->CloseProvider(providerHandle, 0);
}

TEST_F(KspProviderTest, FinalizeKey_InvalidKey_ReturnsInvalidHandle)
{
    NCRYPT_KEY_HANDLE invalidKey = 0xDEADBEEF;
    
    NTSTATUS status = provider_->FinalizeKey(invalidKey, 0);
    EXPECT_EQ(status, STATUS_INVALID_HANDLE);
}

TEST_F(KspProviderTest, DeleteKey_ValidKey_ReturnsSuccess)
{
    NCRYPT_PROV_HANDLE providerHandle = 0;
    NCRYPT_KEY_HANDLE keyHandle = 0;
    
    // Open provider and create key
    NTSTATUS status = provider_->OpenProvider(&providerHandle, nullptr, 0);
    ASSERT_EQ(status, STATUS_SUCCESS);
    
    status = provider_->CreateKey(
        providerHandle,
        &keyHandle,
        NCRYPT_RSA_ALGORITHM,
        L"TestKey",
        0,
        0);
    ASSERT_EQ(status, STATUS_SUCCESS);
    
    // Delete key
    status = provider_->DeleteKey(keyHandle, 0);
    EXPECT_EQ(status, STATUS_SUCCESS);
    
    // Clean up
    provider_->CloseProvider(providerHandle, 0);
}

TEST_F(KspProviderTest, DeleteKey_InvalidKey_ReturnsInvalidHandle)
{
    NCRYPT_KEY_HANDLE invalidKey = 0xDEADBEEF;
    
    NTSTATUS status = provider_->DeleteKey(invalidKey, 0);
    EXPECT_EQ(status, STATUS_INVALID_HANDLE);
}

TEST_F(KspProviderTest, MultipleProviderHandles_IndependentLifecycle)
{
    NCRYPT_PROV_HANDLE provider1 = 0;
    NCRYPT_PROV_HANDLE provider2 = 0;
    
    // Open two providers
    NTSTATUS status1 = provider_->OpenProvider(&provider1, nullptr, 0);
    NTSTATUS status2 = provider_->OpenProvider(&provider2, nullptr, 0);
    
    EXPECT_EQ(status1, STATUS_SUCCESS);
    EXPECT_EQ(status2, STATUS_SUCCESS);
    EXPECT_NE(provider1, 0);
    EXPECT_NE(provider2, 0);
    EXPECT_NE(provider1, provider2);  // Should be different handles
    
    // Close first provider
    status1 = provider_->CloseProvider(provider1, 0);
    EXPECT_EQ(status1, STATUS_SUCCESS);
    
    // Second provider should still be valid
    NCRYPT_KEY_HANDLE keyHandle = 0;
    NTSTATUS status = provider_->CreateKey(
        provider2,
        &keyHandle,
        NCRYPT_RSA_ALGORITHM,
        L"TestKey",
        0,
        0);
    EXPECT_EQ(status, STATUS_SUCCESS);
    
    // Clean up
    if (keyHandle != 0)
    {
        provider_->DeleteKey(keyHandle, 0);
    }
    provider_->CloseProvider(provider2, 0);
}

class KspProviderParameterizedTest : public KspProviderTest,
                                   public ::testing::WithParamInterface<std::wstring>
{
};

TEST_P(KspProviderParameterizedTest, CreateKey_SupportedAlgorithms_ReturnsSuccess)
{
    std::wstring algorithm = GetParam();
    
    NCRYPT_PROV_HANDLE providerHandle = 0;
    NCRYPT_KEY_HANDLE keyHandle = 0;
    
    // Open provider
    NTSTATUS status = provider_->OpenProvider(&providerHandle, nullptr, 0);
    ASSERT_EQ(status, STATUS_SUCCESS);
    
    // Create key with supported algorithm
    status = provider_->CreateKey(
        providerHandle,
        &keyHandle,
        algorithm.c_str(),
        (L"TestKey_" + algorithm).c_str(),
        0,
        0);
    
    EXPECT_EQ(status, STATUS_SUCCESS) << "Failed for algorithm: " << algorithm.c_str();
    EXPECT_NE(keyHandle, 0);
    
    // Clean up
    if (keyHandle != 0)
    {
        provider_->DeleteKey(keyHandle, 0);
    }
    provider_->CloseProvider(providerHandle, 0);
}

INSTANTIATE_TEST_SUITE_P(
    SupportedAlgorithms,
    KspProviderParameterizedTest,
    ::testing::Values(
        NCRYPT_RSA_ALGORITHM,
        NCRYPT_ECDSA_P256_ALGORITHM,
        NCRYPT_ECDSA_P384_ALGORITHM,
        NCRYPT_ECDSA_P521_ALGORITHM
    )
);

} // namespace