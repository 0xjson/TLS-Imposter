package fingerprint

import (
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
	"github.com/bogdanfinn/utls/dicttls"
)

// extraProfiles are profiles the bundled tls-client release does not ship yet.
// Profiles and Lookup merge them with the library's own map.
var extraProfiles = map[string]profiles.ClientProfile{
	"firefox_158": Firefox_158,
}

// Firefox_158 is Firefox 158.0 on Windows, captured off the wire against
// tls.peet.ws:
//
//	ja4     t13d1517h2_8daaf6152771_3cbfd9057e0d
//	ja3     9d42e90b0225e779f03141ddcd699df2
//	akamai  1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
//
// Against firefox_148 the hello drops four CBC suites (both ECDHE_ECDSA CBC
// suites and both DHE_RSA ones) and the two FFDHE groups; everything else,
// extension order included, is unchanged. The HTTP/2 layer measured identical,
// so it is taken from firefox_148, as is HTTP/3, which was not measured.
var Firefox_158 = withHello(profiles.Firefox_148, utls.ClientHelloID{
	Client:  "Firefox",
	Version: "158",
	SpecFactory: func() (utls.ClientHelloSpec, error) {
		return utls.ClientHelloSpec{
			CipherSuites: []uint16{
				utls.TLS_AES_128_GCM_SHA256,
				utls.TLS_CHACHA20_POLY1305_SHA256,
				utls.TLS_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{utls.CompressionNone},
			Extensions: []utls.TLSExtension{
				&utls.SNIExtension{},
				&utls.ExtendedMasterSecretExtension{},
				&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
				&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
					utls.X25519MLKEM768,
					utls.X25519,
					utls.CurveP256,
					utls.CurveP384,
					utls.CurveP521,
				}},
				&utls.SupportedPointsExtension{SupportedPoints: []byte{utls.PointFormatUncompressed}},
				&utls.SessionTicketExtension{},
				&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&utls.StatusRequestExtension{},
				&utls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.ECDSAWithP521AndSHA512,
					utls.ECDSAWithSHA1,
				}},
				&utls.SCTExtension{},
				&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
					{Group: utls.X25519MLKEM768},
					{Group: utls.X25519},
					{Group: utls.CurveP256},
				}},
				&utls.SupportedVersionsExtension{Versions: []uint16{
					utls.VersionTLS13,
					utls.VersionTLS12,
				}},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.ECDSAWithP521AndSHA512,
					utls.PSSWithSHA256,
					utls.PSSWithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA256,
					utls.PKCS1WithSHA384,
					utls.PKCS1WithSHA512,
					utls.ECDSAWithSHA1,
					utls.PKCS1WithSHA1,
				}},
				&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
				&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
				&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
					utls.CertCompressionZlib,
					utls.CertCompressionBrotli,
					utls.CertCompressionZstd,
				}},
				&utls.GREASEEncryptedClientHelloExtension{
					CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{
						{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_AES_128_GCM},
						{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_AES_256_GCM},
						{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_CHACHA20_POLY1305},
					},
					CandidatePayloadLens: []uint16{128, 223},
				},
			},
		}, nil
	},
})

// withHello returns base with its ClientHelloID replaced by id, keeping every
// HTTP/2 and HTTP/3 setting of base.
func withHello(base profiles.ClientProfile, id utls.ClientHelloID) profiles.ClientProfile {
	return profiles.NewClientProfile(
		id,
		base.GetSettings(),
		base.GetSettingsOrder(),
		base.GetPseudoHeaderOrder(),
		base.GetConnectionFlow(),
		base.GetPriorities(),
		base.GetHeaderPriority(),
		base.GetStreamID(),
		base.GetAllowHTTP(),
		base.GetHttp3Settings(),
		base.GetHttp3SettingsOrder(),
		base.GetHttp3PriorityParam(),
		base.GetHttp3PseudoHeaderOrder(),
		base.GetHttp3SendGreaseFrames(),
	)
}
