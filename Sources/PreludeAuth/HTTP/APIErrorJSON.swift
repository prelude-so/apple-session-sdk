import Foundation

struct APIErrorJSON: Decodable {
    var code: String
    var message: String?
    var type: String?
    var requestId: String?

    enum CodingKeys: String, CodingKey {
        case code
        case message
        case type
        case requestId = "request_id"
    }

    var displayMessage: String {
        message.map { $0.isEmpty ? code : $0 } ?? code
    }
}
