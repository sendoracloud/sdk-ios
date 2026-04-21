import Foundation

/// Data returned when a SendoraCloud deep link is handled.
public struct SendoraCloudLinkData {
    public let shortcode: String
    public let deepLinkPath: String?
    public let fallbackUrl: String?
    public let campaign: String?
    public let source: String?
    public let medium: String?
    public let channel: String?
    public let linkData: [String: Any]
    public let clickId: String?

    init(
        shortcode: String,
        deepLinkPath: String? = nil,
        fallbackUrl: String? = nil,
        campaign: String? = nil,
        source: String? = nil,
        medium: String? = nil,
        channel: String? = nil,
        linkData: [String: Any] = [:],
        clickId: String? = nil
    ) {
        self.shortcode = shortcode
        self.deepLinkPath = deepLinkPath
        self.fallbackUrl = fallbackUrl
        self.campaign = campaign
        self.source = source
        self.medium = medium
        self.channel = channel
        self.linkData = linkData
        self.clickId = clickId
    }
}
