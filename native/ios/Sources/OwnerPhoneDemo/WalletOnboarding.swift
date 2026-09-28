/**
 EXPERIMENTAL PREVIEW — onboarding: custody first, then the pairing act.

 Step 1 states the custody fact this launch actually resolved — Enclave,
 explicit simulator key, or plainly unavailable; there is no quiet
 downgrade. Step 2 is the existing pairing behavior: scanning or opening a
 link only fills the form, pairing is still a button, a blocked stored
 pairing must be forgotten explicitly, and every status line comes from
 DemoModel verbatim.

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import OwnerPhone
import SwiftUI

struct WalletOnboardingView: View {
    @ObservedObject var model: DemoModel
    @State private var step = 0
    #if os(iOS)
    @State private var showingPairingScanner = false
    @State private var scannerMessage = ""
    #endif

    var body: some View {
        ZStack {
            WalletTheme.paper.ignoresSafeArea()
            if step == 0 {
                custodyStep.transition(.opacity)
            } else {
                pairStep.transition(.opacity)
            }
        }
        .animation(.easeOut(duration: 0.2), value: step)
        // A scanned or opened pairing link means the owner is ready to pair.
        .onChange(of: model.pairingCodeText) { code in
            if !code.isEmpty, model.ownerKey != nil, !model.storedPairingBlocked { step = 1 }
        }
    }

    // MARK: Step 1 of 2 — the key

    private var custodyStep: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    stepHeader(1, "Owner key")
                    Text("Your phone becomes the key.")
                        .font(WalletTheme.speech(.largeTitle, .bold))
                        .foregroundStyle(WalletTheme.ink)
                        .padding(.top, 12)
                    Text("Apps ask this phone before they can act for your account. You review each request and decide.")
                        .font(WalletTheme.speech(.body))
                        .foregroundStyle(WalletTheme.muted)
                        .padding(.top, 8)

                    VStack(alignment: .leading, spacing: 16) {
                        benefit("key", "No seed phrase to lose",
                                "The key is created on this phone and never leaves it.")
                        benefit("link", "One account, every configured chain",
                                "The same account address on each chain the service runs.")
                        benefit("hand.raised", "Apps ask; you decide",
                                "Apps work only within limits you approve, and you can revoke them.")
                    }
                    .padding(.top, 26)

                    WalletOwnerKeyCard(ownerKey: model.ownerKey).padding(.top, 26)

                    // A blocked stored pairing must stay recoverable even while the
                    // owner key is unavailable — that combination is exactly when the
                    // model demands an explicit local forget, so the control and the
                    // model's own instruction surface here, not only on step 2.
                    if model.storedPairingBlocked {
                        VStack(spacing: 12) {
                            if !model.statusLine.isEmpty {
                                WalletNotice(text: model.statusLine, tone: .warning)
                            }
                            WalletSecondaryButton(title: "Forget blocked pairing", destructive: true) {
                                model.unpair()
                            }
                        }
                        .padding(.top, 14)
                    } else if !model.statusLine.isEmpty {
                        WalletNotice(text: model.statusLine) {
                            model.clearStatusLine()
                        }
                        .padding(.top, 14)
                    }
                }
                .padding(20)
            }
            footer {
                WalletPrimaryButton(
                    title: model.ownerKey == nil ? "Owner key unavailable" : "Continue",
                    enabled: model.ownerKey != nil && !model.storedPairingBlocked
                ) { step = 1 }
                if model.ownerKey == nil {
                    Text("Quit and reopen the app to try creating the key again.")
                        .font(WalletTheme.speech(.footnote))
                        .foregroundStyle(WalletTheme.muted)
                        .multilineTextAlignment(.center)
                }
            }
        }
    }

    private func benefit(_ icon: String, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: icon)
                .font(WalletTheme.speech(.body, .medium))
                .foregroundStyle(WalletTheme.teal)
                .frame(width: 40, height: 40)
                .background(WalletTheme.tealWash)
                .clipShape(RoundedRectangle(cornerRadius: 11, style: .continuous))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(WalletTheme.speech(.headline, .semibold))
                    .foregroundStyle(WalletTheme.ink)
                Text(detail)
                    .font(WalletTheme.speech(.subheadline))
                    .foregroundStyle(WalletTheme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
    }

    // MARK: Step 2 of 2 — pair

    private var canPair: Bool {
        model.ownerKey != nil
            && !model.baseURLText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !model.pairingCodeText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private var pairStep: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    Button {
                        step = 0
                    } label: {
                        Label("Back", systemImage: "chevron.left")
                            .font(WalletTheme.speech(.body, .medium))
                            .frame(minHeight: 44)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(WalletTheme.teal)
                    .disabled(model.pairingInFlight)

                    stepHeader(2, "Pair")
                    Text("Pair with the service.")
                        .font(WalletTheme.speech(.largeTitle, .bold))
                        .foregroundStyle(WalletTheme.ink)
                        .padding(.top, 12)
                    Text("On your Mac, open the service page and choose Pair phone. Scan the QR code it shows, or open its pairing link on this phone.")
                        .font(WalletTheme.speech(.body))
                        .foregroundStyle(WalletTheme.muted)
                        .padding(.top, 8)

                    #if os(iOS)
                    scanButton.padding(.top, 22)
                    #endif

                    fields.padding(.top, 16)

                    Text("The pairing code works once and expires in minutes. Pair only on a network you trust.")
                        .font(WalletTheme.speech(.footnote))
                        .foregroundStyle(WalletTheme.muted)
                        .padding(.top, 12)
                }
                .padding(20)
            }
            #if os(iOS)
            .scrollDismissesKeyboard(.interactively)
            #endif
            footer {
                if !model.statusLine.isEmpty {
                    WalletNotice(text: model.statusLine)
                }
                if model.storedPairingBlocked {
                    WalletSecondaryButton(title: "Forget blocked pairing", destructive: true) {
                        model.unpair()
                    }
                } else {
                    WalletPrimaryButton(
                        title: model.pairingInFlight ? "Pairing…" : "Pair this phone",
                        enabled: canPair,
                        busy: model.pairingInFlight
                    ) {
                        Task { await model.pair() }
                    }
                }
            }
        }
        #if os(iOS)
        .sheet(isPresented: $showingPairingScanner) { scannerSheet }
        #endif
    }

    private var fields: some View {
        WalletCard(padding: 14) {
            VStack(alignment: .leading, spacing: 12) {
                field(
                    "Relay URL", placeholder: "http://192.168.1.20:8787",
                    text: $model.baseURLText)
                field(
                    "Pairing code", placeholder: "Code or oaath-demo:// link",
                    text: $model.pairingCodeText)
            }
        }
    }

    private func field(_ label: String, placeholder: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label)
                .font(WalletTheme.speech(.footnote, .medium))
                .foregroundStyle(WalletTheme.muted)
            TextField(placeholder, text: text)
                .textFieldStyle(.plain)
                .autocorrectionDisabled()
                #if os(iOS)
                .textInputAutocapitalization(.never)
                .keyboardType(.URL)
                #endif
                .font(WalletTheme.mono(.subheadline))
                .foregroundStyle(WalletTheme.ink)
                .padding(12)
                .background(WalletTheme.paper)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                .disabled(model.pairingInFlight)
                .accessibilityLabel(label)
        }
    }

    private func footer<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(spacing: 10) {
            content()
        }
        .padding(.horizontal, 20)
        .padding(.top, 12)
        .padding(.bottom, 12)
        .background(WalletTheme.card)
        .overlay(alignment: .top) { WalletTheme.border.frame(height: 1) }
    }

    #if os(iOS)
    private var scanButton: some View {
        Button {
            scannerMessage = ""
            showingPairingScanner = true
        } label: {
            HStack(spacing: 14) {
                Image(systemName: "qrcode.viewfinder")
                    .font(.system(.title).weight(.regular))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Scan pairing QR")
                        .font(WalletTheme.speech(.headline, .semibold))
                    Text("Fills the fields below. You still confirm with Pair.")
                        .font(WalletTheme.speech(.footnote))
                        .opacity(0.82)
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right")
                    .font(WalletTheme.speech(.footnote, .semibold))
                    .accessibilityHidden(true)
            }
            .foregroundStyle(WalletTheme.inkText)
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(WalletTheme.ink)
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(WalletPressStyle())
        .disabled(model.pairingInFlight)
    }

    private var scannerSheet: some View {
        NavigationStack {
            ZStack(alignment: .bottom) {
                PairingQRCodeScanner { payload in
                    if model.applyScannedPairingPayload(payload) {
                        showingPairingScanner = false
                        return true
                    } else {
                        scannerMessage = "This QR code is not an OAAth pairing link."
                        return false
                    }
                } onFailure: { failure in
                    scannerMessage = failure.message
                }
                .ignoresSafeArea()

                Text(scannerMessage.isEmpty
                    ? "Point the camera at the pairing QR shown on your Mac."
                    : scannerMessage)
                    .font(.footnote)
                    .foregroundStyle(.white)
                    .multilineTextAlignment(.center)
                    .padding()
                    .background(.black.opacity(0.75), in: RoundedRectangle(cornerRadius: 12))
                    .padding()
            }
            .navigationTitle("Scan pairing QR")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { showingPairingScanner = false }
                }
            }
        }
    }
    #endif

    private func stepHeader(_ step: Int, _ label: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                ForEach(1...2, id: \.self) { index in
                    Capsule()
                        .fill(index <= step ? WalletTheme.ink : WalletTheme.track)
                        .frame(height: 4)
                }
            }
            .accessibilityHidden(true)
            Text("Step \(step) of 2 · \(label)")
                .font(WalletTheme.speech(.footnote, .semibold))
                .foregroundStyle(WalletTheme.muted)
        }
        .padding(.top, 8)
    }
}
#endif
