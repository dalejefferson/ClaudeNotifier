//
//  UsageLimitTracker.swift
//  ClaudeNotifier
//
//  Tracks Claude Code's 5-hour rolling usage limit window using real API data.
//

import Foundation
import Combine

/// Tracks the 5-hour rolling usage window for Claude Code.
///
/// This tracker observes `RateLimitFetcher` to get real API utilization data
/// and provides formatted values for the UI.
final class UsageLimitTracker: ObservableObject {

    // MARK: - Published Properties

    /// Percentage of capacity remaining (0.0 to 100.0).
    /// Calculated as 100 - fiveHourUtilization from the API.
    @Published private(set) var percentageRemaining: Double = 100.0

    /// Seconds remaining until the window refreshes.
    @Published private(set) var timeUntilRefresh: TimeInterval = 0

    /// Human-readable formatted time remaining (e.g., "2h 34m").
    @Published private(set) var formattedTimeRemaining: String = "No active window"

    /// Whether there is an active usage window.
    @Published private(set) var isWindowActive: Bool = false

    // MARK: - Private Properties

    /// Cancellables for Combine subscriptions.
    private var cancellables = Set<AnyCancellable>()

    /// Timer for updating countdown every second.
    private var refreshTimer: Timer?

    /// Cached reset date from the fetcher.
    private var resetDate: Date?

    // MARK: - Singleton

    /// Shared instance for app-wide usage limit tracking.
    static let shared = UsageLimitTracker()

    // MARK: - Initialization

    /// Creates a new UsageLimitTracker that observes RateLimitFetcher.
    init() {
        setupFetcherObservation()
        startRefreshTimer()
    }

    deinit {
        refreshTimer?.invalidate()
    }

    // MARK: - Private Methods

    /// Sets up observation of the RateLimitFetcher.
    private func setupFetcherObservation() {
        let fetcher = RateLimitFetcher.shared

        // Observe utilization changes
        fetcher.$fiveHourUtilization
            .receive(on: DispatchQueue.main)
            .sink { [weak self] utilization in
                self?.updateFromUtilization(utilization)
            }
            .store(in: &cancellables)

        // Observe reset date changes
        fetcher.$fiveHourResetsAt
            .receive(on: DispatchQueue.main)
            .sink { [weak self] resetDate in
                self?.resetDate = resetDate
                self?.updateTimeRemaining()
            }
            .store(in: &cancellables)
    }

    /// Starts the timer that updates the countdown every second.
    private func startRefreshTimer() {
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.updateTimeRemaining()
        }

        // Ensure timer runs even when menu is open
        if let timer = refreshTimer {
            RunLoop.main.add(timer, forMode: .common)
        }
    }

    /// Updates percentage remaining from the utilization value.
    ///
    /// - Parameter utilization: Percentage used (0-100) from the API.
    private func updateFromUtilization(_ utilization: Double) {
        // API gives us percentage USED, we want percentage REMAINING
        percentageRemaining = max(0, min(100, 100 - utilization))
        isWindowActive = utilization > 0
    }

    /// Updates time-related properties based on the reset date.
    private func updateTimeRemaining() {
        guard let resetDate = resetDate else {
            timeUntilRefresh = 0
            formattedTimeRemaining = "No active window"
            return
        }

        let remaining = resetDate.timeIntervalSinceNow

        if remaining <= 0 {
            // Window has reset
            timeUntilRefresh = 0
            formattedTimeRemaining = "Window refreshed"
            isWindowActive = false
            return
        }

        timeUntilRefresh = remaining
        formattedTimeRemaining = formatTimeInterval(remaining)
    }

    /// Formats a time interval into a human-readable string.
    ///
    /// - Parameter interval: The time interval in seconds.
    /// - Returns: A formatted string like "2h 34m" or "15m 30s".
    private func formatTimeInterval(_ interval: TimeInterval) -> String {
        guard interval > 0 else {
            return "0s"
        }

        let totalSeconds = Int(interval)
        let hours = totalSeconds / 3600
        let minutes = (totalSeconds % 3600) / 60
        let seconds = totalSeconds % 60

        if hours > 0 {
            return "\(hours)h \(minutes)m"
        } else if minutes > 0 {
            return "\(minutes)m \(seconds)s"
        } else {
            return "\(seconds)s"
        }
    }

    // MARK: - Public Methods

    /// Forces a refresh of the data from the fetcher.
    func refresh() {
        RateLimitFetcher.shared.refresh()
    }

    /// Pauses the countdown timer (for power saving when app is inactive).
    func pause() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }

    /// Resumes the countdown timer.
    func resume() {
        guard refreshTimer == nil else { return }
        startRefreshTimer()
    }
}

// MARK: - Status Level

/// Represents the urgency level of the usage limit status.
enum UsageLimitStatusLevel {
    case good      // > 50% remaining
    case warning   // 20-50% remaining
    case critical  // < 20% remaining
}

// MARK: - Convenience Extensions

extension UsageLimitTracker {

    /// Percentage of capacity used (inverse of remaining).
    var percentageUsed: Double {
        return 100.0 - percentageRemaining
    }

    /// Formatted percentage remaining (e.g., "72%").
    var formattedPercentage: String {
        return "\(Int(percentageRemaining))%"
    }

    /// Formatted time until refresh (alias for formattedTimeRemaining).
    var formattedTimeUntilRefresh: String {
        return formattedTimeRemaining
    }

    /// Returns the status level based on percentage remaining.
    /// - good: > 50% remaining (green)
    /// - warning: 20-50% remaining (yellow)
    /// - critical: < 20% remaining (red)
    var statusLevel: UsageLimitStatusLevel {
        if percentageRemaining > 50 {
            return .good
        } else if percentageRemaining > 20 {
            return .warning
        } else {
            return .critical
        }
    }
}
