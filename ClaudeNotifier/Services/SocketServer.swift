//
//  SocketServer.swift
//  ClaudeNotifier
//
//  Unix domain socket server that listens for events from Claude Code hooks.
//  Uses POSIX sockets for reliable local IPC.
//

import Foundation
import os.log

// MARK: - Notification Names

extension Notification.Name {
    static let claudeEventReceived = Notification.Name("claudeEventReceived")
}

// MARK: - SocketServer

final class SocketServer: ObservableObject {

    // MARK: - Constants

    static let socketPath = "/tmp/claude-notifier.sock"
    private static let maxRecentEvents = 20

    // MARK: - Published Properties

    @MainActor @Published private(set) var lastEvent: ClaudeEvent?
    @MainActor @Published private(set) var isRunning = false
    @MainActor @Published private(set) var recentEvents: [ClaudeEvent] = []

    // MARK: - Private Properties

    private var serverSocket: Int32 = -1
    private var acceptSource: DispatchSourceRead?
    private let logger = Logger(subsystem: "com.claudenotifier", category: "SocketServer")
    private let serverQueue = DispatchQueue(label: "com.claudenotifier.socketserver", qos: .userInitiated)

    private let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    // MARK: - Initialization

    init() {}

    deinit {
        stopSync()
    }

    // MARK: - Public Methods

    @MainActor
    func start() {
        guard !isRunning else {
            logger.warning("Server is already running")
            return
        }

        logger.info("Starting socket server at \(Self.socketPath)")
        removeExistingSocket()

        // Create socket
        serverSocket = socket(AF_UNIX, SOCK_STREAM, 0)
        guard serverSocket >= 0 else {
            logger.error("Failed to create socket: \(String(cString: strerror(errno)))")
            return
        }

        // Bind to path
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        // Copy path to sun_path
        Self.socketPath.withCString { cString in
            withUnsafeMutableBytes(of: &addr.sun_path) { rawBuffer in
                let buffer = rawBuffer.assumingMemoryBound(to: CChar.self)
                let length = min(strlen(cString) + 1, buffer.count)
                strncpy(buffer.baseAddress!, cString, length)
            }
        }

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                bind(serverSocket, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        guard bindResult == 0 else {
            logger.error("Failed to bind socket: \(String(cString: strerror(errno)))")
            close(serverSocket)
            serverSocket = -1
            return
        }

        // Listen for connections
        guard listen(serverSocket, 5) == 0 else {
            logger.error("Failed to listen on socket: \(String(cString: strerror(errno)))")
            close(serverSocket)
            serverSocket = -1
            return
        }

        // Set up dispatch source for accepting connections
        let source = DispatchSource.makeReadSource(fileDescriptor: serverSocket, queue: serverQueue)
        source.setEventHandler { [weak self] in
            self?.acceptConnection()
        }
        source.setCancelHandler { [weak self] in
            if let socket = self?.serverSocket, socket >= 0 {
                close(socket)
            }
            self?.serverSocket = -1
        }
        source.resume()
        acceptSource = source

        isRunning = true
        logger.info("Socket server listening at \(Self.socketPath)")
    }

    @MainActor
    func stop() {
        stopSync()
    }

    private func stopSync() {
        logger.info("Stopping socket server")

        acceptSource?.cancel()
        acceptSource = nil

        if serverSocket >= 0 {
            close(serverSocket)
            serverSocket = -1
        }

        removeExistingSocket()

        Task { @MainActor in
            self.isRunning = false
        }
    }

    @MainActor
    func clearHistory() {
        recentEvents.removeAll()
        lastEvent = nil
    }

    // MARK: - Private Methods

    private func acceptConnection() {
        var clientAddr = sockaddr_un()
        var clientAddrLen = socklen_t(MemoryLayout<sockaddr_un>.size)

        let clientSocket = withUnsafeMutablePointer(to: &clientAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                accept(serverSocket, sockaddrPtr, &clientAddrLen)
            }
        }

        guard clientSocket >= 0 else {
            if errno != EAGAIN && errno != EWOULDBLOCK {
                logger.error("Failed to accept connection: \(String(cString: strerror(errno)))")
            }
            return
        }

        // Handle client in background
        serverQueue.async { [weak self] in
            self?.handleClient(socket: clientSocket)
        }
    }

    private func handleClient(socket clientSocket: Int32) {
        defer { close(clientSocket) }

        var buffer = [UInt8](repeating: 0, count: 65536)
        var accumulated = Data()

        while true {
            let bytesRead = read(clientSocket, &buffer, buffer.count)

            if bytesRead <= 0 {
                break
            }

            accumulated.append(contentsOf: buffer[0..<bytesRead])
        }

        if !accumulated.isEmpty {
            processReceivedData(accumulated)
        }
    }

    private func processReceivedData(_ data: Data) {
        guard let string = String(data: data, encoding: .utf8) else {
            return
        }

        let lines = string.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        for line in lines {
            guard let lineData = line.data(using: .utf8) else { continue }

            do {
                let event = try decoder.decode(ClaudeEvent.self, from: lineData)
                Task { @MainActor in
                    self.handleReceivedEvent(event)
                }
            } catch {
                logger.error("Failed to decode event: \(error.localizedDescription)")
                // Create a fallback notification event
                let fallbackEvent = ClaudeEvent(
                    type: .notification,
                    message: line
                )
                Task { @MainActor in
                    self.handleReceivedEvent(fallbackEvent)
                }
            }
        }
    }

    @MainActor
    private func handleReceivedEvent(_ event: ClaudeEvent) {
        logger.info("Received event: \(event.type.rawValue)")

        lastEvent = event
        recentEvents.append(event)
        if recentEvents.count > Self.maxRecentEvents {
            recentEvents.removeFirst(recentEvents.count - Self.maxRecentEvents)
        }

        NotificationCenter.default.post(
            name: .claudeEventReceived,
            object: event
        )
    }

    private func removeExistingSocket() {
        try? FileManager.default.removeItem(atPath: Self.socketPath)
    }
}
