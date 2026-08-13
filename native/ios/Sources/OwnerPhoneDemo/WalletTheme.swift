/**
 EXPERIMENTAL PREVIEW — the TURN-1 wallet design language as SwiftUI tokens.

 Source of truth: the "OAAth Wallet" Claude Design project
 (`OAAth Wallet.dc.html`, TURN 1). Paper-and-ink receipt: a warm paper
 background, cards on near-white, ink for emphasis, teal for actions the owner
 takes, red for refusal, amber for anything requested-but-unproven. Two voices:
 the system speaks in the default face; anything the chain owns (addresses,
 digests, selectors, wei, codes) is monospaced.

 Deliberate substitution: the design names Instrument Sans and JetBrains Mono.
 This build maps those roles onto the system faces (SF / SF Mono) instead of
 bundling font binaries into the demo target.

 Facts keep their provenance: views built from these tokens label sample data
 explicitly (`WalletSampleBadge`) wherever this preview has no live source.

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import SwiftUI

public enum WalletTheme {
    // MARK: Palette (hex values verbatim from the design doc)
    public static let paper = Color(red: 0xF3 / 255, green: 0xF0 / 255, blue: 0xE9 / 255)
    public static let card = Color(red: 0xFF / 255, green: 0xFD / 255, blue: 0xF7 / 255)
    public static let ink = Color(red: 0x16 / 255, green: 0x16 / 255, blue: 0x0F / 255)
    public static let inkText = Color(red: 0xF3 / 255, green: 0xF0 / 255, blue: 0xE9 / 255)
    public static let border = Color(red: 0xE3 / 255, green: 0xDE / 255, blue: 0xD0 / 255)
    public static let hairline = Color(red: 0xED / 255, green: 0xE8 / 255, blue: 0xDC / 255)
    public static let muted = Color(red: 0x6E / 255, green: 0x69 / 255, blue: 0x5B / 255)
    public static let faint = Color(red: 0x9A / 255, green: 0x94 / 255, blue: 0x86 / 255)
    public static let teal = Color(red: 0x0B / 255, green: 0x6B / 255, blue: 0x62 / 255)
    public static let tealWash = Color(red: 0xE4 / 255, green: 0xEF / 255, blue: 0xEB / 255)
    public static let red = Color(red: 0xC6 / 255, green: 0x37 / 255, blue: 0x1A / 255)
    public static let redWash = Color(red: 0xFB / 255, green: 0xE9 / 255, blue: 0xE3 / 255)
    public static let amber = Color(red: 0xA9 / 255, green: 0x72 / 255, blue: 0x0A / 255)
    public static let amberWash = Color(red: 0xF6 / 255, green: 0xEE / 255, blue: 0xDB / 255)
    public static let chip = Color(red: 0xEF / 255, green: 0xEB / 255, blue: 0xE0 / 255)
    public static let dash = Color(red: 0xC9 / 255, green: 0xC2 / 255, blue: 0xB0 / 255)
    public static let track = Color(red: 0xDF / 255, green: 0xD9 / 255, blue: 0xCA / 255)
    public static let mint = Color(red: 0x5F / 255, green: 0xD3 / 255, blue: 0xA6 / 255)

    // MARK: Type roles
    /// Speech: sentences the app says to the owner.
    public static func speech(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight)
    }

    /// Chain-owned facts: addresses, digests, selectors, codes, wei.
    public static func mono(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced)
    }
}

/// Uppercase monospaced section label, e.g. "ASSETS", "SIGNING POLICY".
struct WalletSectionLabel: View {
    let text: String

    var body: some View {
        Text(text.uppercased())
            .font(WalletTheme.mono(10, .medium))
            .kerning(1.1)
            .foregroundStyle(WalletTheme.muted)
    }
}

/// The card every fact sits on. `emphasized` draws the ink border used for
/// anything awaiting the owner.
struct WalletCard<Content: View>: View {
    var emphasized = false
    var padding: CGFloat = 15
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(WalletTheme.card)
            .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .stroke(emphasized ? WalletTheme.ink : WalletTheme.border, lineWidth: 1)
            )
    }
}

/// Small status chip: INCLUDED / SUBMITTED / ACTIVE / EXPIRED / REJECTED …
struct WalletStatusPill: View {
    let text: String
    let color: Color
    let background: Color

    var body: some View {
        Text(text)
            .font(WalletTheme.mono(10, .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .background(background)
            .clipShape(Capsule())
    }

    static func included() -> WalletStatusPill {
        .init(text: "INCLUDED", color: WalletTheme.teal, background: WalletTheme.tealWash)
    }
    static func submitted() -> WalletStatusPill {
        .init(text: "SUBMITTED", color: WalletTheme.amber, background: WalletTheme.amberWash)
    }
    static func rejected() -> WalletStatusPill {
        .init(text: "REJECTED", color: WalletTheme.red, background: WalletTheme.redWash)
    }
    static func active() -> WalletStatusPill {
        .init(text: "ACTIVE", color: WalletTheme.teal, background: WalletTheme.tealWash)
    }
    static func expired() -> WalletStatusPill {
        .init(text: "EXPIRED", color: WalletTheme.muted, background: WalletTheme.chip)
    }
}

/// Marks a surface whose numbers have no live source in this preview build.
/// Facts keep their provenance; sample data says so out loud.
struct WalletSampleBadge: View {
    var body: some View {
        Text("SAMPLE")
            .font(WalletTheme.mono(9, .semibold))
            .kerning(0.9)
            .foregroundStyle(WalletTheme.amber)
            .padding(.horizontal, 7)
            .padding(.vertical, 4)
            .background(WalletTheme.amberWash)
            .clipShape(Capsule())
    }
}

/// Filled ink action button, the design's primary control.
struct WalletPrimaryButton: View {
    let title: String
    var systemImage: String?
    var enabled = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                if let systemImage {
                    Image(systemName: systemImage).font(.system(size: 14, weight: .medium))
                }
                Text(title).font(WalletTheme.speech(16, .medium))
            }
            .foregroundStyle(WalletTheme.inkText)
            .frame(maxWidth: .infinity)
            .frame(height: 52)
            .background(enabled ? WalletTheme.ink : WalletTheme.track)
            .clipShape(RoundedRectangle(cornerRadius: 15, style: .continuous))
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
    }
}

/// Bordered secondary button; `role: destructive` renders the refusal red.
struct WalletSecondaryButton: View {
    let title: String
    var destructive = false
    var height: CGFloat = 42
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(WalletTheme.speech(14, .medium))
                .foregroundStyle(destructive ? WalletTheme.red : WalletTheme.ink)
                .frame(maxWidth: .infinity)
                .frame(height: height)
                .overlay(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(destructive ? WalletTheme.red : WalletTheme.border, lineWidth: 1)
                )
        }
        .buttonStyle(.plain)
    }
}
#endif
