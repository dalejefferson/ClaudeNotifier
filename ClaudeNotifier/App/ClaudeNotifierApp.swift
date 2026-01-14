//
//  ClaudeNotifierApp.swift
//  ClaudeNotifier
//
//  Main application entry point for Claude Notifier.
//

import SwiftUI

@main
struct ClaudeNotifierApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(socketServer: appDelegate.socketServer)
        } label: {
            MenuBarLabel(socketServer: appDelegate.socketServer)
        }
        .menuBarExtraStyle(.window)
    }
}

// MARK: - Menu Bar Label

struct MenuBarLabel: View {
    @ObservedObject var socketServer: SocketServer

    var body: some View {
        Text("●")
            .font(.system(size: 14))
            .foregroundColor(socketServer.isRunning ? .green : .red)
            .help(socketServer.isRunning ? "Claude Notifier: Listening" : "Claude Notifier: Not Running")
    }
}
