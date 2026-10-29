package msg

// 翻訳キーの一覧です。
//
// 命名は診断結果が "analyzer.<診断種別>.<対象>.<用途>"、
// APIのエラー応答が "api.error.<種別>" です。
// ここに定義したキーは frontend/src/i18n/locales/en.json と ja.json の
// 両方に存在しなければならず、TestAllKeysExistInLocales で検証されます。
// 新しいメッセージを追加するときは、定数・AllKeys・両辞書の3箇所を更新してください。

// APIのエラー応答のキー。
const (
	// APIMethodNotAllowed は params["allowed"]（許可メソッド）を取ります。
	APIMethodNotAllowed  = "api.error.method_not_allowed"
	APIInvalidURL        = "api.error.invalid_url"
	APIUnsupportedScheme = "api.error.unsupported_scheme"
	APINoHost            = "api.error.no_host"
	APIHostRequired      = "api.error.host_required"
	APIJWTRequired       = "api.error.jwt_required"
	// APIBlockedAddress は params["ip"]（拒否したアドレス）を取ります。
	APIBlockedAddress = "api.error.blocked_address"
	// APIResolveFailed は params["host"] を取ります。
	APIResolveFailed = "api.error.resolve_failed"
	// APIValidationFailed は params["reason"] を取ります。想定外の検証エラー用です。
	APIValidationFailed = "api.error.validation_failed"
	// APIScanFailed は params["reason"] を取ります。
	APIScanFailed  = "api.error.scan_failed"
	APIRateLimited = "api.error.rate_limited"
)

// セキュリティヘッダー診断のキー。
const (
	HeaderHSTSDesc               = "analyzer.header.hsts.desc"
	HeaderHSTSAdviceMissing      = "analyzer.header.hsts.advice.missing"
	HeaderHSTSAdviceMaxAgeZero   = "analyzer.header.hsts.advice.max_age_zero"
	HeaderHSTSAdviceNoPreload    = "analyzer.header.hsts.advice.no_preload"
	HeaderHSTSAdviceNoSubdomains = "analyzer.header.hsts.advice.no_subdomains"

	HeaderCSPDesc                   = "analyzer.header.csp.desc"
	HeaderCSPAdviceMissing          = "analyzer.header.csp.advice.missing"
	HeaderCSPAdviceUnsafeInlineEval = "analyzer.header.csp.advice.unsafe_inline_and_eval"
	HeaderCSPAdviceUnsafeEither     = "analyzer.header.csp.advice.unsafe_inline_or_eval"
	HeaderCSPAdviceNoDefaultSrc     = "analyzer.header.csp.advice.no_default_src"

	HeaderXFrameOptionsDesc             = "analyzer.header.x_frame_options.desc"
	HeaderXFrameOptionsAdviceMissing    = "analyzer.header.x_frame_options.advice.missing"
	HeaderXFrameOptionsAdviceWeakValue  = "analyzer.header.x_frame_options.advice.weak_value"
	HeaderXContentTypeDesc              = "analyzer.header.x_content_type_options.desc"
	HeaderXContentTypeAdviceMissing     = "analyzer.header.x_content_type_options.advice.missing"
	HeaderXContentTypeAdviceNotNosniff  = "analyzer.header.x_content_type_options.advice.not_nosniff"
	HeaderReferrerPolicyDesc            = "analyzer.header.referrer_policy.desc"
	HeaderReferrerPolicyAdviceMissing   = "analyzer.header.referrer_policy.advice.missing"
	HeaderReferrerPolicyAdviceWeakValue = "analyzer.header.referrer_policy.advice.weak_value"

	HeaderPermissionsPolicyDesc          = "analyzer.header.permissions_policy.desc"
	HeaderPermissionsPolicyAdviceMissing = "analyzer.header.permissions_policy.advice.missing"

	HeaderXXSSProtectionDesc            = "analyzer.header.x_xss_protection.desc"
	HeaderXXSSProtectionAdviceMissing   = "analyzer.header.x_xss_protection.advice.missing"
	HeaderXXSSProtectionAdviceWeakValue = "analyzer.header.x_xss_protection.advice.weak_value"

	HeaderCacheControlDesc             = "analyzer.header.cache_control.desc"
	HeaderCacheControlAdviceMissing    = "analyzer.header.cache_control.advice.missing"
	HeaderCacheControlAdviceAddNoStore = "analyzer.header.cache_control.advice.add_no_store"
	HeaderCacheControlAdviceWeakValue  = "analyzer.header.cache_control.advice.weak_value"
)

// CORSミスコンフィグ診断のキー。
const (
	CORSTestOriginReflectionName = "analyzer.cors.test.origin_reflection.name"
	CORSTestOriginReflectionDesc = "analyzer.cors.test.origin_reflection.desc"
	CORSTestNullOriginName       = "analyzer.cors.test.null_origin.name"
	CORSTestNullOriginDesc       = "analyzer.cors.test.null_origin.desc"
	CORSTestPreDomainName        = "analyzer.cors.test.pre_domain.name"
	CORSTestPreDomainDesc        = "analyzer.cors.test.pre_domain.desc"
	CORSTestPostDomainName       = "analyzer.cors.test.post_domain.name"
	CORSTestPostDomainDesc       = "analyzer.cors.test.post_domain.desc"

	// CORSDetailACAO は params["acao"] を取ります。
	CORSDetailACAO = "analyzer.cors.detail.acao"
	// CORSDetailACAOWithACAC は params["acao"] を取ります。
	CORSDetailACAOWithACAC = "analyzer.cors.detail.acao_with_acac"
	// CORSDetailRequestFailed は params["error"] を取ります。
	CORSDetailRequestFailed = "analyzer.cors.detail.request_failed"
)

// JWT解析のキー。
const (
	JWTParseErrorInvalidParts = "analyzer.jwt.parse_error.invalid_parts"
	// JWTParseErrorHeaderDecode は params["error"] を取ります。
	JWTParseErrorHeaderDecode = "analyzer.jwt.parse_error.header_decode"
	// JWTParseErrorPayloadDecode は params["error"] を取ります。
	JWTParseErrorPayloadDecode = "analyzer.jwt.parse_error.payload_decode"

	JWTAlgNoneTitle = "analyzer.jwt.finding.alg_none.title"
	JWTAlgNoneDesc  = "analyzer.jwt.finding.alg_none.desc"
	// JWTAlgSymmetricTitle は params["alg"] を取ります。
	JWTAlgSymmetricTitle = "analyzer.jwt.finding.alg_symmetric.title"
	JWTAlgSymmetricDesc  = "analyzer.jwt.finding.alg_symmetric.desc"
	// JWTAlgAsymmetricTitle は params["alg"] を取ります。
	JWTAlgAsymmetricTitle = "analyzer.jwt.finding.alg_asymmetric.title"
	JWTAlgAsymmetricDesc  = "analyzer.jwt.finding.alg_asymmetric.desc"

	JWTKidInjectionTitle = "analyzer.jwt.finding.kid_injection.title"
	// JWTKidInjectionDesc は params["kid"] を取ります。
	JWTKidInjectionDesc = "analyzer.jwt.finding.kid_injection.desc"

	JWTExpiredTitle = "analyzer.jwt.finding.token_expired.title"
	// JWTExpiredDesc は params["expires_at"] を取ります。
	JWTExpiredDesc     = "analyzer.jwt.finding.token_expired.desc"
	JWTLongExpiryTitle = "analyzer.jwt.finding.long_expiry.title"
	// JWTLongExpiryDesc は params["expires_at"] を取ります。
	JWTLongExpiryDesc = "analyzer.jwt.finding.long_expiry.desc"
	JWTNoExpTitle     = "analyzer.jwt.finding.no_exp.title"
	JWTNoExpDesc      = "analyzer.jwt.finding.no_exp.desc"

	JWTNbfFutureTitle = "analyzer.jwt.finding.nbf_future.title"
	// JWTNbfFutureDesc は params["not_before"] を取ります。
	JWTNbfFutureDesc = "analyzer.jwt.finding.nbf_future.desc"

	// JWTSensitiveClaimTitle は params["claim"] を取ります。
	JWTSensitiveClaimTitle = "analyzer.jwt.finding.sensitive_claim.title"
	JWTSensitiveClaimDesc  = "analyzer.jwt.finding.sensitive_claim.desc"

	JWTNoIssuesTitle = "analyzer.jwt.finding.no_issues.title"
	JWTNoIssuesDesc  = "analyzer.jwt.finding.no_issues.desc"
)

// TLS/SSL診断のキー。
const (
	// SSLConnectError は params["error"] を取ります。
	SSLConnectError = "analyzer.ssl.connect_error"

	// SSLLegacyTLSTitle は params["version"] を取ります。
	SSLLegacyTLSTitle = "analyzer.ssl.finding.legacy_tls.title"
	SSLLegacyTLSDesc  = "analyzer.ssl.finding.legacy_tls.desc"
	SSLTLS12Title     = "analyzer.ssl.finding.tls12.title"
	SSLTLS12Desc      = "analyzer.ssl.finding.tls12.desc"
	SSLTLS13Title     = "analyzer.ssl.finding.tls13.title"
	SSLTLS13Desc      = "analyzer.ssl.finding.tls13.desc"

	// SSLWeakCipherTitle は params["cipher"] を取ります。
	SSLWeakCipherTitle = "analyzer.ssl.finding.weak_cipher.title"
	SSLWeakCipherDesc  = "analyzer.ssl.finding.weak_cipher.desc"

	SSLSelfSignedTitle = "analyzer.ssl.finding.self_signed.title"
	SSLSelfSignedDesc  = "analyzer.ssl.finding.self_signed.desc"

	SSLCertExpiredTitle = "analyzer.ssl.finding.cert_expired.title"
	// SSLCertExpiredDesc は params["count"] を取ります。
	SSLCertExpiredDesc = "analyzer.ssl.finding.cert_expired.desc"
	// SSLCertExpiringCriticalTitle は params["count"] を取ります。
	SSLCertExpiringCriticalTitle = "analyzer.ssl.finding.cert_expiring_critical.title"
	SSLCertExpiringCriticalDesc  = "analyzer.ssl.finding.cert_expiring_critical.desc"
	// SSLCertExpiringHighTitle は params["count"] を取ります。
	SSLCertExpiringHighTitle = "analyzer.ssl.finding.cert_expiring_high.title"
	SSLCertExpiringHighDesc  = "analyzer.ssl.finding.cert_expiring_high.desc"
	// SSLCertExpiringWarningTitle は params["count"] を取ります。
	SSLCertExpiringWarningTitle = "analyzer.ssl.finding.cert_expiring_warning.title"
	SSLCertExpiringWarningDesc  = "analyzer.ssl.finding.cert_expiring_warning.desc"
	// SSLCertValidTitle は params["count"] を取ります。
	SSLCertValidTitle = "analyzer.ssl.finding.cert_valid.title"
	// SSLCertValidDesc は params["date"] を取ります。
	SSLCertValidDesc = "analyzer.ssl.finding.cert_valid.desc"

	SSLHostnameMismatchTitle = "analyzer.ssl.finding.hostname_mismatch.title"
	// SSLHostnameMismatchDesc は params["host"] を取ります。
	SSLHostnameMismatchDesc = "analyzer.ssl.finding.hostname_mismatch.desc"

	SSLRSAKeyTitle   = "analyzer.ssl.finding.rsa_key.title"
	SSLRSAKeyDesc    = "analyzer.ssl.finding.rsa_key.desc"
	SSLECDSAKeyTitle = "analyzer.ssl.finding.ecdsa_key.title"
	SSLECDSAKeyDesc  = "analyzer.ssl.finding.ecdsa_key.desc"

	// SSLLegacyAcceptedTitle は params["protocol"] を取ります。
	SSLLegacyAcceptedTitle = "analyzer.ssl.finding.legacy_accepted.title"
	// SSLLegacyAcceptedDesc は params["protocol"] を取ります。
	SSLLegacyAcceptedDesc = "analyzer.ssl.finding.legacy_accepted.desc"
)

// Cookie監査のキー。
const (
	CookieIssueNoSecure               = "analyzer.cookie.issue.no_secure"
	CookieIssueNoHTTPOnly             = "analyzer.cookie.issue.no_http_only"
	CookieIssueNoHTTPOnlySensitive    = "analyzer.cookie.issue.no_http_only_sensitive"
	CookieIssueSameSiteNone           = "analyzer.cookie.issue.same_site_none"
	CookieIssueSameSiteNoneSensitive  = "analyzer.cookie.issue.same_site_none_sensitive"
	CookieIssueSameSiteUnset          = "analyzer.cookie.issue.same_site_unset"
	CookieIssueSameSiteUnsetSensitive = "analyzer.cookie.issue.same_site_unset_sensitive"
)

// AllKeys はこのパッケージが定義する全キーの一覧です。
// 辞書との整合性テストと、翻訳漏れの検出に使います。
var AllKeys = []string{
	APIMethodNotAllowed,
	APIInvalidURL,
	APIUnsupportedScheme,
	APINoHost,
	APIHostRequired,
	APIJWTRequired,
	APIBlockedAddress,
	APIResolveFailed,
	APIValidationFailed,
	APIScanFailed,
	APIRateLimited,

	HeaderHSTSDesc,
	HeaderHSTSAdviceMissing,
	HeaderHSTSAdviceMaxAgeZero,
	HeaderHSTSAdviceNoPreload,
	HeaderHSTSAdviceNoSubdomains,
	HeaderCSPDesc,
	HeaderCSPAdviceMissing,
	HeaderCSPAdviceUnsafeInlineEval,
	HeaderCSPAdviceUnsafeEither,
	HeaderCSPAdviceNoDefaultSrc,
	HeaderXFrameOptionsDesc,
	HeaderXFrameOptionsAdviceMissing,
	HeaderXFrameOptionsAdviceWeakValue,
	HeaderXContentTypeDesc,
	HeaderXContentTypeAdviceMissing,
	HeaderXContentTypeAdviceNotNosniff,
	HeaderReferrerPolicyDesc,
	HeaderReferrerPolicyAdviceMissing,
	HeaderReferrerPolicyAdviceWeakValue,
	HeaderPermissionsPolicyDesc,
	HeaderPermissionsPolicyAdviceMissing,
	HeaderXXSSProtectionDesc,
	HeaderXXSSProtectionAdviceMissing,
	HeaderXXSSProtectionAdviceWeakValue,
	HeaderCacheControlDesc,
	HeaderCacheControlAdviceMissing,
	HeaderCacheControlAdviceAddNoStore,
	HeaderCacheControlAdviceWeakValue,

	CORSTestOriginReflectionName,
	CORSTestOriginReflectionDesc,
	CORSTestNullOriginName,
	CORSTestNullOriginDesc,
	CORSTestPreDomainName,
	CORSTestPreDomainDesc,
	CORSTestPostDomainName,
	CORSTestPostDomainDesc,
	CORSDetailACAO,
	CORSDetailACAOWithACAC,
	CORSDetailRequestFailed,

	JWTParseErrorInvalidParts,
	JWTParseErrorHeaderDecode,
	JWTParseErrorPayloadDecode,
	JWTAlgNoneTitle,
	JWTAlgNoneDesc,
	JWTAlgSymmetricTitle,
	JWTAlgSymmetricDesc,
	JWTAlgAsymmetricTitle,
	JWTAlgAsymmetricDesc,
	JWTKidInjectionTitle,
	JWTKidInjectionDesc,
	JWTExpiredTitle,
	JWTExpiredDesc,
	JWTLongExpiryTitle,
	JWTLongExpiryDesc,
	JWTNoExpTitle,
	JWTNoExpDesc,
	JWTNbfFutureTitle,
	JWTNbfFutureDesc,
	JWTSensitiveClaimTitle,
	JWTSensitiveClaimDesc,
	JWTNoIssuesTitle,
	JWTNoIssuesDesc,

	SSLConnectError,
	SSLLegacyTLSTitle,
	SSLLegacyTLSDesc,
	SSLTLS12Title,
	SSLTLS12Desc,
	SSLTLS13Title,
	SSLTLS13Desc,
	SSLWeakCipherTitle,
	SSLWeakCipherDesc,
	SSLSelfSignedTitle,
	SSLSelfSignedDesc,
	SSLCertExpiredTitle,
	SSLCertExpiredDesc,
	SSLCertExpiringCriticalTitle,
	SSLCertExpiringCriticalDesc,
	SSLCertExpiringHighTitle,
	SSLCertExpiringHighDesc,
	SSLCertExpiringWarningTitle,
	SSLCertExpiringWarningDesc,
	SSLCertValidTitle,
	SSLCertValidDesc,
	SSLHostnameMismatchTitle,
	SSLHostnameMismatchDesc,
	SSLRSAKeyTitle,
	SSLRSAKeyDesc,
	SSLECDSAKeyTitle,
	SSLECDSAKeyDesc,
	SSLLegacyAcceptedTitle,
	SSLLegacyAcceptedDesc,

	CookieIssueNoSecure,
	CookieIssueNoHTTPOnly,
	CookieIssueNoHTTPOnlySensitive,
	CookieIssueSameSiteNone,
	CookieIssueSameSiteNoneSensitive,
	CookieIssueSameSiteUnset,
	CookieIssueSameSiteUnsetSensitive,
}
