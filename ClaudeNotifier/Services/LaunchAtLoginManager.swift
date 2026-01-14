//
//  LaunchAtLoginManager.swift
//  ClaudeNotifier
//
//  Manages Launch at Login functionality using SMAppService (macOS 13+).
//

import Foundation
import AppKit
import ServiceManagement

/// Manages the "Launch at Login" functionality.
///
/// Uses SMAppService for modern macOS login item management.
/// Requires the app to be located in /Applications or ~/Applications.
final class LaunchAtLoginManager: ObservableObject {

    // MARK: - Published Properties

    /// Whether launch at login is currently enabled.
    @Published private(set) var isEnabled: Bool = false

    /// Human-readable status description.
    @Published private(set) var statusMessage: String = ""

    // MARK: - Singleton

    /// Shared instance for app-wide access.
    static let shared = LaunchAtLoginManager()

    // MARK: - Initialization

    private init() {
        refreshStatus()
    }

    // MARK: - Public Methods

    /// Enables or disables launch at login.
    ///
    /// - Parameter enabled: Whether to enable or disable.
    func setEnabled(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            refreshStatus()
        } catch {
            print("LaunchAtLoginManager: Failed to \(enabled ? "enable" : "disable"): \(error.localizedDescription)")
            statusMessage = "Failed: \(error.localizedDescription)"
        }
    }

    /// Toggles the current state.
    func toggle() {
        setEnabled(!isEnabled)
    }

    /// Refreshes the current status from the system.
    func refreshStatus() {
        let status = SMAppService.mainApp.status

        switch status {
        case .enabled:
            isEnabled = true
            statusMessage = "Enabled"
        case .notRegistered:
            isEnabled = false
            statusMessage = "Disabled"
        case .requiresApproval:
            isEnabled = false
            statusMessage = "Requires approval in System Settings"
        case .notFound:
            isEnabled = false
            statusMessage = "App not found (must be in Applications)"
        @unknown default:
            isEnabled = false
            statusMessage = "Unknown status"
        }
    }

    /// Whether the status requires user action.
    var requiresUserAction: Bool {
        let status = SMAppService.mainApp.status
        return status == .requiresApproval || status == .notFound
    }

    /// Opens System Settings to the Login Items section.
    func openSystemSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }
}
