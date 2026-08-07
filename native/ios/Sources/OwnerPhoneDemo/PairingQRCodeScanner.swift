/**
 EXPERIMENTAL PREVIEW — in-app QR capture for the existing pairing-link parser.

 The camera is only a byte source. This boundary emits a QR string and never
 interprets it, pairs a device, or mutates authority; DemoModel routes it
 through the exact PairingLink parser before filling candidate fields.

 @author taek <leekt216@gmail.com>
 */
#if os(iOS)
import AVFoundation
import SwiftUI
import UIKit

enum PairingQRCodeScannerFailure: Equatable {
    case cameraUnavailable
    case permissionDenied
    case configurationFailed

    var message: String {
        switch self {
        case .cameraUnavailable:
            return "No camera is available. Cancel and paste the pairing link instead."
        case .permissionDenied:
            return "Camera access is off. Enable it in Settings, or paste the pairing link."
        case .configurationFailed:
            return "The camera could not start. Cancel and paste the pairing link instead."
        }
    }
}

struct PairingQRCodeScanner: UIViewControllerRepresentable {
    /// Returns true only after the strict pairing-link boundary accepted the
    /// payload. Acceptance latches and terminates capture.
    let onPayload: (String) -> Bool
    let onFailure: (PairingQRCodeScannerFailure) -> Void

    func makeUIViewController(context: Context) -> PairingQRCodeScannerViewController {
        PairingQRCodeScannerViewController(
            onPayload: onPayload,
            onFailure: onFailure)
    }

    func updateUIViewController(
        _ uiViewController: PairingQRCodeScannerViewController,
        context: Context
    ) {}

    static func dismantleUIViewController(
        _ uiViewController: PairingQRCodeScannerViewController,
        coordinator: Void
    ) {
        uiViewController.stop()
    }
}

final class PairingQRCodeScannerViewController: UIViewController,
    AVCaptureMetadataOutputObjectsDelegate
{
    private let captureSession = AVCaptureSession()
    private let sessionQueue = DispatchQueue(label: "org.oaath.owner-phone.qr-camera")
    private lazy var previewLayer = AVCaptureVideoPreviewLayer(session: captureSession)
    private let onPayload: (String) -> Bool
    private let onFailure: (PairingQRCodeScannerFailure) -> Void
    private var configured = false
    /// Read and written only on sessionQueue.
    private var stopped = false
    /// Metadata delivery is on the main queue.
    private var accepted = false
    private var acceptingPayloads = true
    private var lastPayload: String?
    private var lastPayloadTime: TimeInterval = 0
    private var runtimeErrorObserver: NSObjectProtocol?

    init(
        onPayload: @escaping (String) -> Bool,
        onFailure: @escaping (PairingQRCodeScannerFailure) -> Void
    ) {
        self.onPayload = onPayload
        self.onFailure = onFailure
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is unavailable")
    }

    deinit {
        if let runtimeErrorObserver {
            NotificationCenter.default.removeObserver(runtimeErrorObserver)
        }
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        previewLayer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(previewLayer)
        observeRuntimeErrors()
        requestCamera()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer.frame = view.bounds
    }

    func stop() {
        acceptingPayloads = false
        sessionQueue.async { [weak self] in
            guard let self else { return }
            self.stopped = true
            if self.captureSession.isRunning { self.captureSession.stopRunning() }
        }
    }

    private func requestCamera() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            configureAndStart()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                guard let self else { return }
                if granted {
                    self.configureAndStart()
                } else {
                    self.report(.permissionDenied)
                }
            }
        case .denied, .restricted:
            report(.permissionDenied)
        @unknown default:
            report(.configurationFailed)
        }
    }

    private func configureAndStart() {
        sessionQueue.async { [weak self] in
            guard let self, !self.stopped else { return }
            if self.configured {
                if !self.captureSession.isRunning, !self.stopped {
                    self.captureSession.startRunning()
                }
                return
            }
            guard let camera = AVCaptureDevice.default(for: .video) else {
                self.report(.cameraUnavailable)
                return
            }
            guard let input = try? AVCaptureDeviceInput(device: camera) else {
                self.report(.configurationFailed)
                return
            }

            let output = AVCaptureMetadataOutput()
            self.captureSession.beginConfiguration()
            guard self.captureSession.canAddInput(input),
                  self.captureSession.canAddOutput(output)
            else {
                self.captureSession.commitConfiguration()
                self.report(.configurationFailed)
                return
            }
            self.captureSession.addInput(input)
            self.captureSession.addOutput(output)
            guard output.availableMetadataObjectTypes.contains(.qr) else {
                self.captureSession.commitConfiguration()
                self.report(.configurationFailed)
                return
            }
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
            self.captureSession.commitConfiguration()
            self.configured = true
            guard !self.stopped else { return }
            self.captureSession.startRunning()
        }
    }

    private func observeRuntimeErrors() {
        runtimeErrorObserver = NotificationCenter.default.addObserver(
            forName: AVCaptureSession.runtimeErrorNotification,
            object: captureSession,
            queue: nil
        ) { [weak self] _ in
            self?.sessionQueue.async { [weak self] in
                guard let self, !self.stopped else { return }
                self.stopped = true
                if self.captureSession.isRunning { self.captureSession.stopRunning() }
                self.report(.configurationFailed)
            }
        }
    }

    private func report(_ failure: PairingQRCodeScannerFailure) {
        DispatchQueue.main.async { [weak self] in
            guard let self, self.acceptingPayloads else { return }
            self.onFailure(failure)
        }
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard acceptingPayloads, !accepted,
              let code = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              code.type == .qr,
              let payload = code.stringValue
        else {
            return
        }
        let now = ProcessInfo.processInfo.systemUptime
        guard payload != lastPayload || now - lastPayloadTime > 1.5 else { return }
        lastPayload = payload
        lastPayloadTime = now
        if onPayload(payload) {
            accepted = true
            stop()
        }
    }
}
#endif
