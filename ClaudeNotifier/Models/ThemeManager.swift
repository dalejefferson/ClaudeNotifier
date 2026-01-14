//
//  ThemeManager.swift
//  ClaudeNotifier
//

import SwiftUI
import Combine

@MainActor
final class ThemeManager: ObservableObject {
    static let shared = ThemeManager()

    @AppStorage("selectedPaletteId") private var storedPaletteId: String = "warm-professional"

    @Published private(set) var palette: ColorPalette

    var currentPaletteId: String {
        get { storedPaletteId }
        set {
            storedPaletteId = newValue
            palette = ColorPalette.allPalettes.first { $0.id == newValue } ?? .warmProfessional
        }
    }

    private init() {
        let savedId = UserDefaults.standard.string(forKey: "selectedPaletteId") ?? "warm-professional"
        self.palette = ColorPalette.allPalettes.first { $0.id == savedId } ?? .warmProfessional
    }

    func setPalette(_ newPalette: ColorPalette) {
        storedPaletteId = newPalette.id
        palette = newPalette
    }
}
