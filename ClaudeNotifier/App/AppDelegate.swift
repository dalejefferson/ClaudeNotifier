//
//  AppDelegate.swift
//  ClaudeNotifier
//
//  Application delegate managing socket server, session tracking,
//  and notification window presentation.
//

import AppKit
import SwiftUI

// MARK: - AppDelegate

final class AppDelegate: NSObject, NSApplicationDelegate {

    // MARK: - Properties

    let socketServer = SocketServer()
    private let sessionTracker = SessionTracker.shared
    private var notificationWindow: NSWindow?
    private var eventObserver: NSObjectProtocol?

    // MARK: - Lifecycle

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Cleanup old events
        EventStore.shared.performCleanup()

        // Start the socket server
        Task { @MainActor in
            socketServer.start()
        }

        // Observe Claude events
        eventObserver = NotificationCenter.default.addObserver(
            forName: .claudeEventReceived,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let event = notification.object as? ClaudeEvent else { return }
            self?.handleClaudeEvent(event)
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        // Flush all pending batched writes
        EventStore.shared.flushToDisk()
        SessionTracker.shared.flush()

        if let observer = eventObserver {
            NotificationCenter.default.removeObserver(observer)
            eventObserver = nil
        }
        Task { @MainActor in
            socketServer.stop()
        }
        sessionTracker.save()
    }

    // MARK: - Event Handling

    private func handleClaudeEvent(_ event: ClaudeEvent) {
        // Track subagents: if we see activity from an unknown session that isn't a main session start,
        // it's likely a subagent. Register it so we can count active agents.
        if event.type != .sessionStart && !event.sessionId.isEmpty {
            if !sessionTracker.isTracking(sessionId: event.sessionId) {
                // This session isn't a main session - it's a subagent
                sessionTracker.recordSubagentStart(sessionId: event.sessionId)
            }
        }

        switch event.type {
        case .sessionStart:
            // Record session start time, no notification
            sessionTracker.recordStart(sessionId: event.sessionId, timestamp: event.timestamp)
            return

        case .notification:
            // Skip idle prompt notifications - only notify on finished generations
            if event.matcher == .idlePrompt {
                return
            }
            fallthrough

        case .subagentStop:
            // Track subagent completion - remove from active count
            sessionTracker.recordSubagentStop(sessionId: event.sessionId)
            // Don't show notification for subagent completions
            return

        case .stop:
            // Enrich event with session data
            var enrichedEvent = event

            // Add duration
            if let duration = sessionTracker.getDuration(sessionId: event.sessionId) {
                enrichedEvent.duration = duration
            }

            // Clear session if completed (do this before async work)
            if event.stopReason != .interrupt {
                sessionTracker.clearSession(sessionId: event.sessionId)
            }

            // Add task summary from transcript if available (background thread)
            if enrichedEvent.taskSummary == nil && !event.transcriptPath.isEmpty {
                // Parse transcript on background thread to avoid blocking UI
                DispatchQueue.global(qos: .utility).async { [weak self] in
                    let (summary, _, _) = TranscriptParser.parseTranscript(at: event.transcriptPath)

                    DispatchQueue.main.async {
                        var finalEvent = enrichedEvent
                        finalEvent.taskSummary = summary

                        // Persist enriched event to history
                        EventStore.shared.save(event: finalEvent)

                        // Show notification window
                        self?.showNotificationWindow(for: finalEvent)
                    }
                }
            } else {
                // No transcript parsing needed - save and show immediately
                EventStore.shared.save(event: enrichedEvent)
                showNotificationWindow(for: enrichedEvent)
            }
        }
    }

    // MARK: - Window Management

    private func showNotificationWindow(for event: ClaudeEvent) {
        closeNotificationWindow()

        let contentView = NotificationWindowView(event: event) { [weak self] in
            self?.closeNotificationWindow()
        }
        .padding(20) // Padding for shadow to render

        // Window size: card width (360) + shadow padding (40) x estimated height
        let windowWidth: CGFloat = 400
        let windowHeight: CGFloat = 180

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: windowWidth, height: windowHeight),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )

        // Configure borderless transparent window
        window.isOpaque = false
        window.backgroundColor = .clear
        window.hasShadow = false // We use SwiftUI shadows
        window.level = .floating
        window.collectionBehavior = [.canJoinAllSpaces, .stationary]
        window.contentView = NSHostingView(rootView: contentView)

        // Position in top-right corner
        if let screen = NSScreen.main {
            let screenFrame = screen.visibleFrame
            let x = screenFrame.maxX - windowWidth - 10
            let y = screenFrame.maxY - windowHeight - 10
            window.setFrameOrigin(NSPoint(x: x, y: y))
        }

        window.isReleasedWhenClosed = false

        notificationWindow = window
        stealFocus(window: window)
    }

    private func closeNotificationWindow() {
        notificationWindow?.close()
        notificationWindow = nil
    }

    private func stealFocus(window: NSWindow) {
        // Activate the application
        NSApp.activate(ignoringOtherApps: true)

        // Make window key and bring to front
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()

        // Temporarily set to screen saver level
        window.level = .screenSaver

        // Reset to floating level after brief delay
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak window] in
            window?.level = .floating
        }

        // Play audio alert
        NSSound.beep()
    }
}
