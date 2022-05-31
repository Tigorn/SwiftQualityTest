import Foundation

final class EncryptionKeyFetcher {

    private enum Const {
        static let beginKey = "-----BEGIN PUBLIC KEY-----"
        static let endKey = "-----END PUBLIC KEY-----"
        static let beginCertificate = "-----BEGIN CERTIFICATE-----"
        static let endCertificate = "-----END CERTIFICATE-----"
    }

    func fetch(from rawKey: String) throws -> [UInt8] {
        if isCertificate(rawKey) {
            var key = rawKey
            key = key.replacingOccurrences(of: Const.beginCertificate, with: "")
            key = key.replacingOccurrences(of: Const.endCertificate, with: "")
            key = key.replacingOccurrences(of: "\r", with: "")
            key = key.replacingOccurrences(of: "\n", with: "")
            key = key.replacingOccurrences(of: "\t", with: "")
            key = key.replacingOccurrences(of: " ", with: "")
            return key.toBytesArray()
        }
        if isPubKey(rawKey) {
            var key = rawKey
            key = key.replacingOccurrences(of: Const.beginKey, with: "")
            key = key.replacingOccurrences(of: Const.endKey, with: "")
            key = key.replacingOccurrences(of: "\r", with: "")
            key = key.replacingOccurrences(of: "\n", with: "")
            key = key.replacingOccurrences(of: "\t", with: "")
            key = key.replacingOccurrences(of: " ", with: "")
            return key.toBytesArray()
        }
        throw Error.unexpectedFormat
    }

    private func isCertificate(_ rawKey: String) -> Bool {
        rawKey.contains(Const.beginCertificate) && rawKey.contains(Const.endCertificate)
    }

    private func isPubKey(_ rawKey: String) -> Bool {
        rawKey.contains(Const.beginKey) && rawKey.contains(Const.endKey)
    }
}

extension EncryptionKeyFetcher {
    enum Error: CustomNSError, LocalizedError {
        case unexpectedFormat

        // MARK: - CustomNSError

        static var errorDomain: String {
            "EKF"
        }

        var errorCode: Int {
            switch self {
            case .unexpectedFormat:
                return 0
            }
        }

        var errorUserInfo: [String: Any] {
            switch self {
            case .unexpectedFormat:
                return [:]
            }
        }

        // MARK: - LocalizedError

        var errorDescription: String? {
            "\(Self.errorDomain)-\(errorCode)"
        }
    }
}