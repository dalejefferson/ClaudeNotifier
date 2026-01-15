//
//  RateLimitFetcher.swift
//  ClaudeNotifier
//
//  Created on 2026-01-14.
//

import Foundation
import Combine
import Security

/// Fetches real Claude API usage data from the Anthropic OAuth usage endpoint
class RateLimitFetcher: ObservableObject {

    // MARK: - Singleton

    static let shared = RateLimitFetcher()

    // MARK: - Published Properties

    @Published var fiveHourUtilization: Double = 0.0
    @Published var fiveHourResetsAt: Date?
    @Published var sevenDayUtilization: Double = 0.0
    @Published var sevenDayResetsAt: Date?
    @Published var timeUntilReset: TimeInterval = 0
    @Published var formattedTimeUntilReset: String = "--"
    @Published var isLoading: Bool = false
    @Published var lastError: String?
    @Published var hasValidCredentials: Bool = false

    // MARK: - Private Properties

    private var timer: Timer?
    private var cancellables = Set<AnyCancellable>()

    // Adaptive polling with exponential backoff
    private var currentInterval: TimeInterval = 60.0
    private let minInterval: TimeInterval = 60.0
    private let maxInterval: TimeInterval = 300.0
    private var consecutiveErrors = 0

    private var cachedAccessToken: String?
    private var tokenLastFetched: Date?
    private let tokenCacheInterval: TimeInterval = 3600  // Cache token for 1 hour

    private let apiEndpoint = "https://api.anthropic.com/api/oauth/usage"
    private let keychainService = "Claude Code-credentials"

    // Static formatters (avoid recreation on each call)
    private static let iso8601Formatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    private static let iso8601FormatterNoFractional: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    // MARK: - Response Models

    private struct UsageResponse: Codable {
        let fiveHour: UsageWindow
        let sevenDay: UsageWindow

        enum CodingKeys: String, CodingKey {
            case fiveHour = "five_hour"
            case sevenDay = "seven_day"
        }
    }

    private struct UsageWindow: Codable {
        let utilization: Double
        let resetsAt: String

        enum CodingKeys: String, CodingKey {
            case utilization
            case resetsAt = "resets_at"
        }
    }

    private struct KeychainCredentials: Codable {
        let claudeAiOauth: OAuthCredentials?

        struct OAuthCredentials: Codable {
            let accessToken: String?
        }
    }

    // MARK: - Initialization

    private init() {
        startPeriodicRefresh()
    }

    deinit {
        timer?.invalidate()
    }

    // MARK: - Public Methods

    /// Manually trigger a refresh of usage data
    func refresh() {
        fetchUsageData()
    }

    /// Start the periodic refresh timer
    func startPeriodicRefresh() {
        // Fetch immediately
        fetchUsageData()

        // Set up periodic refresh with adaptive interval
        scheduleNextFetch()
    }

    /// Reschedules the timer with the current interval (for adaptive polling)
    private func scheduleNextFetch() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: currentInterval, repeats: false) { [weak self] _ in
            self?.fetchUsageData()
            self?.scheduleNextFetch()
        }
    }

    /// Handle successful fetch - reset backoff
    private func handleFetchSuccess() {
        consecutiveErrors = 0
        currentInterval = minInterval
    }

    /// Handle fetch error - apply exponential backoff
    private func handleFetchError() {
        consecutiveErrors += 1
        currentInterval = min(currentInterval * 1.5, maxInterval)
        print("RateLimitFetcher: Error #\(consecutiveErrors), backing off to \(Int(currentInterval))s")
    }

    /// Stop the periodic refresh timer
    func stopPeriodicRefresh() {
        timer?.invalidate()
        timer = nil
    }

    // MARK: - Private Methods

    private func fetchUsageData() {
        guard !isLoading else { return }

        DispatchQueue.main.async {
            self.isLoading = true
            self.lastError = nil
        }

        // Get access token from Keychain
        guard let accessToken = getAccessTokenFromKeychain() else {
            DispatchQueue.main.async {
                self.isLoading = false
                self.lastError = "Failed to retrieve access token from Keychain"
                self.hasValidCredentials = false
            }
            return
        }

        DispatchQueue.main.async {
            self.hasValidCredentials = true
        }

        // Create request
        guard let url = URL(string: apiEndpoint) else {
            DispatchQueue.main.async {
                self.isLoading = false
                self.lastError = "Invalid API endpoint URL"
            }
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue("oauth-2025-04-20", forHTTPHeaderField: "anthropic-beta")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("claude-code/2.0.32", forHTTPHeaderField: "User-Agent")

        // Perform request
        URLSession.shared.dataTaskPublisher(for: request)
            .tryMap { data, response -> Data in
                guard let httpResponse = response as? HTTPURLResponse else {
                    throw URLError(.badServerResponse)
                }

                guard (200...299).contains(httpResponse.statusCode) else {
                    let errorMessage = String(data: data, encoding: .utf8) ?? "Unknown error"
                    throw NSError(
                        domain: "RateLimitFetcher",
                        code: httpResponse.statusCode,
                        userInfo: [NSLocalizedDescriptionKey: "HTTP \(httpResponse.statusCode): \(errorMessage)"]
                    )
                }

                return data
            }
            .decode(type: UsageResponse.self, decoder: JSONDecoder())
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { [weak self] completion in
                    self?.isLoading = false
                    if case .failure(let error) = completion {
                        self?.lastError = error.localizedDescription
                        self?.handleFetchError()
                        print("RateLimitFetcher error: \(error)")
                    } else {
                        self?.handleFetchSuccess()
                    }
                },
                receiveValue: { [weak self] response in
                    self?.processResponse(response)
                }
            )
            .store(in: &cancellables)
    }

    private func processResponse(_ response: UsageResponse) {
        // Debug: Log raw API response values
        print("RateLimitFetcher: API Response - 5h raw: \(response.fiveHour.utilization), 7d raw: \(response.sevenDay.utilization)")

        // API returns utilization as percentage (0-100), convert to decimal (0-1)
        // e.g., API returns 60.0 for 60% used, we store as 0.6
        fiveHourUtilization = response.fiveHour.utilization / 100.0
        fiveHourResetsAt = parseISO8601Date(response.fiveHour.resetsAt)

        // Update seven day data (also convert from percentage to decimal)
        sevenDayUtilization = response.sevenDay.utilization / 100.0
        sevenDayResetsAt = parseISO8601Date(response.sevenDay.resetsAt)

        // Debug: Log converted values
        print("RateLimitFetcher: Converted - 5h: \(fiveHourUtilization) (remaining: \(Int((1.0 - fiveHourUtilization) * 100))%), 7d: \(sevenDayUtilization) (remaining: \(Int((1.0 - sevenDayUtilization) * 100))%)")

        // Calculate time until reset (use the earlier reset time - five hour)
        updateTimeUntilReset()
    }

    private func updateTimeUntilReset() {
        guard let resetDate = fiveHourResetsAt else {
            timeUntilReset = 0
            formattedTimeUntilReset = "--"
            return
        }

        let interval = resetDate.timeIntervalSinceNow
        timeUntilReset = max(0, interval)
        formattedTimeUntilReset = formatTimeInterval(timeUntilReset)
    }

    private func parseISO8601Date(_ dateString: String) -> Date? {
        // Use static formatters to avoid recreation
        if let date = Self.iso8601Formatter.date(from: dateString) {
            return date
        }

        // Try without fractional seconds
        return Self.iso8601FormatterNoFractional.date(from: dateString)
    }

    private func formatTimeInterval(_ interval: TimeInterval) -> String {
        guard interval > 0 else { return "0m" }

        let hours = Int(interval) / 3600
        let minutes = (Int(interval) % 3600) / 60

        if hours > 0 {
            return "\(hours)h \(minutes)m"
        } else {
            return "\(minutes)m"
        }
    }

    // MARK: - Keychain Access

    private func getAccessTokenFromKeychain() -> String? {
        // Return cached token if still valid
        if let cached = cachedAccessToken,
           let lastFetched = tokenLastFetched,
           Date().timeIntervalSince(lastFetched) < tokenCacheInterval {
            return cached
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data else {
            print("RateLimitFetcher: Failed to retrieve Keychain item. Status: \(status)")
            // Try reading from local cache file as fallback
            return getTokenFromLocalCache()
        }

        // Parse the JSON to extract the access token
        do {
            let credentials = try JSONDecoder().decode(KeychainCredentials.self, from: data)
            if let token = credentials.claudeAiOauth?.accessToken {
                // Cache the token
                cachedAccessToken = token
                tokenLastFetched = Date()
                // Also save to local cache for persistence
                saveTokenToLocalCache(token)
                return token
            }
            return nil
        } catch {
            print("RateLimitFetcher: Failed to parse Keychain credentials: \(error)")
            return getTokenFromLocalCache()
        }
    }

    // MARK: - Local Token Cache

    private var localCachePath: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent(".claude-notifier-token-cache")
    }

    private func saveTokenToLocalCache(_ token: String) {
        do {
            let data = token.data(using: .utf8)
            try data?.write(to: localCachePath, options: [.atomic])
            // Set restrictive permissions
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: localCachePath.path
            )
        } catch {
            print("RateLimitFetcher: Failed to save token cache: \(error)")
        }
    }

    private func getTokenFromLocalCache() -> String? {
        do {
            let data = try Data(contentsOf: localCachePath)
            return String(data: data, encoding: .utf8)
        } catch {
            return nil
        }
    }

    /// Clear cached credentials (call this if auth fails)
    func clearCachedCredentials() {
        cachedAccessToken = nil
        tokenLastFetched = nil
        try? FileManager.default.removeItem(at: localCachePath)
    }
}
