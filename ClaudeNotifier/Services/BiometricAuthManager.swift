//
//  BiometricAuthManager.swift
//  ClaudeNotifier
//
//  Created on 2026-01-18.
//

import Foundation
import LocalAuthentication
import Security

/// Manages Touch ID authentication with automatic password fallback
/// and biometric-protected keychain storage
class BiometricAuthManager {

    // MARK: - Singleton

    static let shared = BiometricAuthManager()

    // MARK: - Private Properties

    private var cachedContext: LAContext?
    private var contextCreatedAt: Date?
    private let contextCacheInterval: TimeInterval = 3600  // Cache for 1 hour

    private let authReason = "Access your Claude API credentials"

    // Our own biometric-protected keychain item
    private let biometricKeychainService = "ClaudeNotifier-biometric-token"
    private let biometricKeychainAccount = "claude-api-token"

    // MARK: - Initialization

    private init() {}

    // MARK: - Public Methods

    /// Check if biometric authentication is available
    var isBiometricAvailable: Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    /// Check if we have a biometric-protected token stored
    var hasBiometricToken: Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: biometricKeychainService,
            kSecAttrAccount as String: biometricKeychainAccount,
            kSecReturnData as String: false
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Store a token with biometric protection (Touch ID)
    func storeBiometricToken(_ token: String) -> Bool {
        // First delete any existing item
        deleteBiometricToken()

        guard let tokenData = token.data(using: .utf8) else { return false }

        // Create access control with biometric + device passcode fallback
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet, .or, .devicePasscode],
            &error
        ) else {
            print("BiometricAuthManager: Failed to create access control - \(error?.takeRetainedValue().localizedDescription ?? "unknown")")
            return false
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: biometricKeychainService,
            kSecAttrAccount as String: biometricKeychainAccount,
            kSecValueData as String: tokenData,
            kSecAttrAccessControl as String: accessControl
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecSuccess {
            print("BiometricAuthManager: Token stored with biometric protection")
            return true
        } else {
            print("BiometricAuthManager: Failed to store token - \(status)")
            return false
        }
    }

    /// Retrieve token using Touch ID authentication
    /// Returns nil if auth fails/cancelled
    func getBiometricToken() -> String? {
        let context = LAContext()
        context.localizedReason = authReason
        context.localizedCancelTitle = "Cancel"

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: biometricKeychainService,
            kSecAttrAccount as String: biometricKeychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            if let data = result as? Data, let token = String(data: data, encoding: .utf8) {
                print("BiometricAuthManager: Token retrieved with biometric auth")
                return token
            }
        case errSecUserCanceled:
            print("BiometricAuthManager: User cancelled biometric auth")
        case errSecAuthFailed:
            print("BiometricAuthManager: Biometric auth failed")
        case errSecItemNotFound:
            print("BiometricAuthManager: No biometric token stored")
        default:
            print("BiometricAuthManager: Keychain error - \(status)")
        }

        return nil
    }

    /// Delete the biometric-protected token
    func deleteBiometricToken() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: biometricKeychainService,
            kSecAttrAccount as String: biometricKeychainAccount
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Clear the cached authentication context and biometric token
    func clearAuthState() {
        cachedContext = nil
        contextCreatedAt = nil
        deleteBiometricToken()
        print("BiometricAuthManager: Auth state and biometric token cleared")
    }

    /// Check if we have a valid cached authentication
    var hasValidCachedAuth: Bool {
        guard let createdAt = contextCreatedAt else { return false }
        return Date().timeIntervalSince(createdAt) < contextCacheInterval
    }
}
