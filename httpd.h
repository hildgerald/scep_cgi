#ifndef SCEP_HTTPD_H
#define SCEP_HTTPD_H

#include <stdint.h>

#include <openssl/bio.h>

#define MINIMUM_HEADER_LENGTH	(100)

/**
 * @defgroup httpcode HTTP response codes.
 * These are the status codes defined for HTTP responses.
 * See: https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
 * Registry export date: 2021-12-19
 * @{
 */

/* 100 "Continue".            RFC-ietf-httpbis-semantics, Section 15.2.1. */
#define MHD_HTTP_CONTINUE                    100
/* 101 "Switching Protocols". RFC-ietf-httpbis-semantics, Section 15.2.2. */
#define MHD_HTTP_SWITCHING_PROTOCOLS         101
/* 102 "Processing".          RFC2518. */
#define MHD_HTTP_PROCESSING                  102
/* 103 "Early Hints".         RFC8297. */
#define MHD_HTTP_EARLY_HINTS                 103

/* 200 "OK".                  RFC-ietf-httpbis-semantics, Section 15.3.1. */
#define MHD_HTTP_OK                          200
/* 201 "Created".             RFC-ietf-httpbis-semantics, Section 15.3.2. */
#define MHD_HTTP_CREATED                     201
/* 202 "Accepted".            RFC-ietf-httpbis-semantics, Section 15.3.3. */
#define MHD_HTTP_ACCEPTED                    202
/* 203 "Non-Authoritative Information". RFC-ietf-httpbis-semantics, Section 15.3.4. */
#define MHD_HTTP_NON_AUTHORITATIVE_INFORMATION 203
/* 204 "No Content".          RFC-ietf-httpbis-semantics, Section 15.3.5. */
#define MHD_HTTP_NO_CONTENT                  204
/* 205 "Reset Content".       RFC-ietf-httpbis-semantics, Section 15.3.6. */
#define MHD_HTTP_RESET_CONTENT               205
/* 206 "Partial Content".     RFC-ietf-httpbis-semantics, Section 15.3.7. */
#define MHD_HTTP_PARTIAL_CONTENT             206
/* 207 "Multi-Status".        RFC4918. */
#define MHD_HTTP_MULTI_STATUS                207
/* 208 "Already Reported".    RFC5842. */
#define MHD_HTTP_ALREADY_REPORTED            208

/* 226 "IM Used".             RFC3229. */
#define MHD_HTTP_IM_USED                     226

/* 300 "Multiple Choices".    RFC-ietf-httpbis-semantics, Section 15.4.1. */
#define MHD_HTTP_MULTIPLE_CHOICES            300
/* 301 "Moved Permanently".   RFC-ietf-httpbis-semantics, Section 15.4.2. */
#define MHD_HTTP_MOVED_PERMANENTLY           301
/* 302 "Found".               RFC-ietf-httpbis-semantics, Section 15.4.3. */
#define MHD_HTTP_FOUND                       302
/* 303 "See Other".           RFC-ietf-httpbis-semantics, Section 15.4.4. */
#define MHD_HTTP_SEE_OTHER                   303
/* 304 "Not Modified".        RFC-ietf-httpbis-semantics, Section 15.4.5. */
#define MHD_HTTP_NOT_MODIFIED                304
/* 305 "Use Proxy".           RFC-ietf-httpbis-semantics, Section 15.4.6. */
#define MHD_HTTP_USE_PROXY                   305
/* 306 "Switch Proxy".        Not used! RFC-ietf-httpbis-semantics, Section 15.4.7. */
#define MHD_HTTP_SWITCH_PROXY                306
/* 307 "Temporary Redirect".  RFC-ietf-httpbis-semantics, Section 15.4.8. */
#define MHD_HTTP_TEMPORARY_REDIRECT          307
/* 308 "Permanent Redirect".  RFC-ietf-httpbis-semantics, Section 15.4.9. */
#define MHD_HTTP_PERMANENT_REDIRECT          308

/* 400 "Bad Request".         RFC-ietf-httpbis-semantics, Section 15.5.1. */
#define MHD_HTTP_BAD_REQUEST                 400
/* 401 "Unauthorized".        RFC-ietf-httpbis-semantics, Section 15.5.2. */
#define MHD_HTTP_UNAUTHORIZED                401
/* 402 "Payment Required".    RFC-ietf-httpbis-semantics, Section 15.5.3. */
#define MHD_HTTP_PAYMENT_REQUIRED            402
/* 403 "Forbidden".           RFC-ietf-httpbis-semantics, Section 15.5.4. */
#define MHD_HTTP_FORBIDDEN                   403
/* 404 "Not Found".           RFC-ietf-httpbis-semantics, Section 15.5.5. */
#define MHD_HTTP_NOT_FOUND                   404
/* 405 "Method Not Allowed".  RFC-ietf-httpbis-semantics, Section 15.5.6. */
#define MHD_HTTP_METHOD_NOT_ALLOWED          405
/* 406 "Not Acceptable".      RFC-ietf-httpbis-semantics, Section 15.5.7. */
#define MHD_HTTP_NOT_ACCEPTABLE              406
/* 407 "Proxy Authentication Required". RFC-ietf-httpbis-semantics, Section 15.5.8. */
#define MHD_HTTP_PROXY_AUTHENTICATION_REQUIRED 407
/* 408 "Request Timeout".     RFC-ietf-httpbis-semantics, Section 15.5.9. */
#define MHD_HTTP_REQUEST_TIMEOUT             408
/* 409 "Conflict".            RFC-ietf-httpbis-semantics, Section 15.5.10. */
#define MHD_HTTP_CONFLICT                    409
/* 410 "Gone".                RFC-ietf-httpbis-semantics, Section 15.5.11. */
#define MHD_HTTP_GONE                        410
/* 411 "Length Required".     RFC-ietf-httpbis-semantics, Section 15.5.12. */
#define MHD_HTTP_LENGTH_REQUIRED             411
/* 412 "Precondition Failed". RFC-ietf-httpbis-semantics, Section 15.5.13. */
#define MHD_HTTP_PRECONDITION_FAILED         412
/* 413 "Content Too Large".   RFC-ietf-httpbis-semantics, Section 15.5.14. */
#define MHD_HTTP_CONTENT_TOO_LARGE           413
/* 414 "URI Too Long".        RFC-ietf-httpbis-semantics, Section 15.5.15. */
#define MHD_HTTP_URI_TOO_LONG                414
/* 415 "Unsupported Media Type". RFC-ietf-httpbis-semantics, Section 15.5.16. */
#define MHD_HTTP_UNSUPPORTED_MEDIA_TYPE      415
/* 416 "Range Not Satisfiable". RFC-ietf-httpbis-semantics, Section 15.5.17. */
#define MHD_HTTP_RANGE_NOT_SATISFIABLE       416
/* 417 "Expectation Failed".  RFC-ietf-httpbis-semantics, Section 15.5.18. */
#define MHD_HTTP_EXPECTATION_FAILED          417


/* 421 "Misdirected Request". RFC-ietf-httpbis-semantics, Section 15.5.20. */
#define MHD_HTTP_MISDIRECTED_REQUEST         421
/* 422 "Unprocessable Content". RFC-ietf-httpbis-semantics, Section 15.5.21. */
#define MHD_HTTP_UNPROCESSABLE_CONTENT       422
/* 423 "Locked".              RFC4918. */
#define MHD_HTTP_LOCKED                      423
/* 424 "Failed Dependency".   RFC4918. */
#define MHD_HTTP_FAILED_DEPENDENCY           424
/* 425 "Too Early".           RFC8470. */
#define MHD_HTTP_TOO_EARLY                   425
/* 426 "Upgrade Required".    RFC-ietf-httpbis-semantics, Section 15.5.22. */
#define MHD_HTTP_UPGRADE_REQUIRED            426

/* 428 "Precondition Required". RFC6585. */
#define MHD_HTTP_PRECONDITION_REQUIRED       428
/* 429 "Too Many Requests".   RFC6585. */
#define MHD_HTTP_TOO_MANY_REQUESTS           429

/* 431 "Request Header Fields Too Large". RFC6585. */
#define MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE 431

/* 451 "Unavailable For Legal Reasons". RFC7725. */
#define MHD_HTTP_UNAVAILABLE_FOR_LEGAL_REASONS 451

/* 500 "Internal Server Error". RFC-ietf-httpbis-semantics, Section 15.6.1. */
#define MHD_HTTP_INTERNAL_SERVER_ERROR       500
/* 501 "Not Implemented".     RFC-ietf-httpbis-semantics, Section 15.6.2. */
#define MHD_HTTP_NOT_IMPLEMENTED             501
/* 502 "Bad Gateway".         RFC-ietf-httpbis-semantics, Section 15.6.3. */
#define MHD_HTTP_BAD_GATEWAY                 502
/* 503 "Service Unavailable". RFC-ietf-httpbis-semantics, Section 15.6.4. */
#define MHD_HTTP_SERVICE_UNAVAILABLE         503
/* 504 "Gateway Timeout".     RFC-ietf-httpbis-semantics, Section 15.6.5. */
#define MHD_HTTP_GATEWAY_TIMEOUT             504
/* 505 "HTTP Version Not Supported". RFC-ietf-httpbis-semantics, Section 15.6.6. */
#define MHD_HTTP_HTTP_VERSION_NOT_SUPPORTED  505
/* 506 "Variant Also Negotiates". RFC2295. */
#define MHD_HTTP_VARIANT_ALSO_NEGOTIATES     506
/* 507 "Insufficient Storage". RFC4918. */
#define MHD_HTTP_INSUFFICIENT_STORAGE        507
/* 508 "Loop Detected".       RFC5842. */
#define MHD_HTTP_LOOP_DETECTED               508

/* 510 "Not Extended".        RFC2774. */
#define MHD_HTTP_NOT_EXTENDED                510
/* 511 "Network Authentication Required". RFC6585. */
#define MHD_HTTP_NETWORK_AUTHENTICATION_REQUIRED 511


/* Not registered non-standard codes */
/* 449 "Reply With".          MS IIS extension. */
#define MHD_HTTP_RETRY_WITH                  449

/* 450 "Blocked by Windows Parental Controls". MS extension. */
#define MHD_HTTP_BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS 450

/* 509 "Bandwidth Limit Exceeded". Apache extension. */
#define MHD_HTTP_BANDWIDTH_LIMIT_EXCEEDED    509

/* Deprecated names and codes */
/** @deprecated */
#define MHD_HTTP_METHOD_NOT_ACCEPTABLE   406

/** @deprecated */
#define MHD_HTTP_REQUEST_ENTITY_TOO_LARGE   413

/** @deprecated */
#define MHD_HTTP_PAYLOAD_TOO_LARGE   413

/** @deprecated */
#define MHD_HTTP_REQUEST_URI_TOO_LONG   414

/** @deprecated */
#define MHD_HTTP_REQUESTED_RANGE_NOT_SATISFIABLE   416

/** @deprecated */
#define MHD_HTTP_UNPROCESSABLE_ENTITY   422

/** @deprecated */
#define MHD_HTTP_UNORDERED_COLLECTION   425

/** @deprecated */
#define MHD_HTTP_NO_RESPONSE   444


/** @} */ /* end of group httpcode */

/**
 * Specification for how MHD should treat the memory buffer
 * given for the response.
 * @ingroup response
 */
//enum MHD_ResponseMemoryMode
//{
//
//  /**
//   * Buffer is a persistent (static/global) buffer that won't change
//   * for at least the lifetime of the response, MHD should just use
//   * it, not free it, not copy it, just keep an alias to it.
//   * @ingroup response
//   */
//  MHD_RESPMEM_PERSISTENT,
//
//  /**
//   * Buffer is heap-allocated with `malloc()` (or equivalent) and
//   * should be freed by MHD after processing the response has
//   * concluded (response reference counter reaches zero).
//   * @ingroup response
//   */
//  MHD_RESPMEM_MUST_FREE,
//
//  /**
//   * Buffer is in transient memory, but not on the heap (for example,
//   * on the stack or non-`malloc()` allocated) and only valid during the
//   * call to #MHD_create_response_from_buffer.  MHD must make its
//   * own private copy of the data for processing.
//   * @ingroup response
//   */
//  MHD_RESPMEM_MUST_COPY
//
//} _MHD_FIXED_ENUM;

/**
 * @defgroup headers HTTP headers
 * These are the standard headers found in HTTP requests and responses.
 * See: https://www.iana.org/assignments/http-fields/http-fields.xhtml
 * Registry export date: 2021-12-19
 * @{
 */

/* Main HTTP headers. */
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 12.5.1 */
#define MHD_HTTP_HEADER_ACCEPT       "Accept"
/* Deprecated.    RFC-ietf-httpbis-semantics-19, Section 12.5.2 */
#define MHD_HTTP_HEADER_ACCEPT_CHARSET "Accept-Charset"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 12.5.3 */
#define MHD_HTTP_HEADER_ACCEPT_ENCODING "Accept-Encoding"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 12.5.4 */
#define MHD_HTTP_HEADER_ACCEPT_LANGUAGE "Accept-Language"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 14.3 */
#define MHD_HTTP_HEADER_ACCEPT_RANGES "Accept-Ranges"
/* Permanent.     RFC-ietf-httpbis-cache-19, Section 5.1 */
#define MHD_HTTP_HEADER_AGE          "Age"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.2.1 */
#define MHD_HTTP_HEADER_ALLOW        "Allow"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 11.6.3 */
#define MHD_HTTP_HEADER_AUTHENTICATION_INFO "Authentication-Info"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 11.6.2 */
#define MHD_HTTP_HEADER_AUTHORIZATION "Authorization"
/* Permanent.     RFC-ietf-httpbis-cache-19, Section 5.2 */
#define MHD_HTTP_HEADER_CACHE_CONTROL "Cache-Control"
/* Permanent.     RFC-ietf-httpbis-cache-header-10 */
#define MHD_HTTP_HEADER_CACHE_STATUS "Cache-Status"
/* Permanent.     RFC-ietf-httpbis-messaging-19, Section 9.6 */
#define MHD_HTTP_HEADER_CLOSE        "Close"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 7.6.1 */
#define MHD_HTTP_HEADER_CONNECTION   "Connection"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 8.4 */
#define MHD_HTTP_HEADER_CONTENT_ENCODING "Content-Encoding"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 8.5 */
#define MHD_HTTP_HEADER_CONTENT_LANGUAGE "Content-Language"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 8.6 */
#define MHD_HTTP_HEADER_CONTENT_LENGTH "Content-Length"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 8.7 */
#define MHD_HTTP_HEADER_CONTENT_LOCATION "Content-Location"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 14.4 */
#define MHD_HTTP_HEADER_CONTENT_RANGE "Content-Range"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 8.3 */
#define MHD_HTTP_HEADER_CONTENT_TYPE "Content-Type"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 6.6.1 */
#define MHD_HTTP_HEADER_DATE         "Date"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 8.8.3 */
#define MHD_HTTP_HEADER_ETAG         "ETag"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.1.1 */
#define MHD_HTTP_HEADER_EXPECT       "Expect"
/* Permanent.     RFC-ietf-httpbis-expect-ct-08 */
#define MHD_HTTP_HEADER_EXPECT_CT    "Expect-CT"
/* Permanent.     RFC-ietf-httpbis-cache-19, Section 5.3 */
#define MHD_HTTP_HEADER_EXPIRES      "Expires"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.1.2 */
#define MHD_HTTP_HEADER_FROM         "From"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 7.2 */
#define MHD_HTTP_HEADER_HOST         "Host"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 13.1.1 */
#define MHD_HTTP_HEADER_IF_MATCH     "If-Match"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 13.1.3 */
#define MHD_HTTP_HEADER_IF_MODIFIED_SINCE "If-Modified-Since"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 13.1.2 */
#define MHD_HTTP_HEADER_IF_NONE_MATCH "If-None-Match"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 13.1.5 */
#define MHD_HTTP_HEADER_IF_RANGE     "If-Range"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 13.1.4 */
#define MHD_HTTP_HEADER_IF_UNMODIFIED_SINCE "If-Unmodified-Since"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 8.8.2 */
#define MHD_HTTP_HEADER_LAST_MODIFIED "Last-Modified"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.2.2 */
#define MHD_HTTP_HEADER_LOCATION     "Location"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 7.6.2 */
#define MHD_HTTP_HEADER_MAX_FORWARDS "Max-Forwards"
/* Permanent.     RFC-ietf-httpbis-messaging-19, Appendix B.1 */
#define MHD_HTTP_HEADER_MIME_VERSION "MIME-Version"
/* Permanent.     RFC-ietf-httpbis-cache-19, Section 5.4 */
#define MHD_HTTP_HEADER_PRAGMA       "Pragma"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 11.7.1 */
#define MHD_HTTP_HEADER_PROXY_AUTHENTICATE "Proxy-Authenticate"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 11.7.3 */
#define MHD_HTTP_HEADER_PROXY_AUTHENTICATION_INFO "Proxy-Authentication-Info"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 11.7.2 */
#define MHD_HTTP_HEADER_PROXY_AUTHORIZATION "Proxy-Authorization"
/* Permanent.     RFC-ietf-httpbis-proxy-status-08 */
#define MHD_HTTP_HEADER_PROXY_STATUS "Proxy-Status"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 14.2 */
#define MHD_HTTP_HEADER_RANGE        "Range"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.1.3 */
#define MHD_HTTP_HEADER_REFERER      "Referer"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.2.3 */
#define MHD_HTTP_HEADER_RETRY_AFTER  "Retry-After"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.2.4 */
#define MHD_HTTP_HEADER_SERVER       "Server"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.1.4 */
#define MHD_HTTP_HEADER_TE           "TE"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 6.6.2 */
#define MHD_HTTP_HEADER_TRAILER      "Trailer"
/* Permanent.     RFC-ietf-httpbis-messaging-19, Section 6.1 */
#define MHD_HTTP_HEADER_TRANSFER_ENCODING "Transfer-Encoding"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 7.8 */
#define MHD_HTTP_HEADER_UPGRADE      "Upgrade"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.1.5 */
#define MHD_HTTP_HEADER_USER_AGENT   "User-Agent"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 12.5.5 */
#define MHD_HTTP_HEADER_VARY         "Vary"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 7.6.3 */
#define MHD_HTTP_HEADER_VIA          "Via"
/* Obsoleted.     RFC-ietf-httpbis-cache-19, Section 5.5 */
#define MHD_HTTP_HEADER_WARNING      "Warning"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 11.6.1 */
#define MHD_HTTP_HEADER_WWW_AUTHENTICATE "WWW-Authenticate"
/* Permanent.     RFC-ietf-httpbis-semantics-19, Section 12.5.5 */
#define MHD_HTTP_HEADER_ASTERISK     "*"

/* Additional HTTP headers. */
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_A_IM         "A-IM"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_ACCEPT_ADDITIONS "Accept-Additions"
/* Permanent.     RFC8942, Section 3.1 */
#define MHD_HTTP_HEADER_ACCEPT_CH    "Accept-CH"
/* Permanent.     RFC7089 */
#define MHD_HTTP_HEADER_ACCEPT_DATETIME "Accept-Datetime"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_ACCEPT_FEATURES "Accept-Features"
/* Permanent.     https://www.w3.org/TR/ldp/ */
#define MHD_HTTP_HEADER_ACCEPT_POST  "Accept-Post"
/* Permanent.     https://fetch.spec.whatwg.org/#http-access-control-allow-credentials */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS \
  "Access-Control-Allow-Credentials"
/* Permanent.     https://fetch.spec.whatwg.org/#http-access-control-allow-headers */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS \
  "Access-Control-Allow-Headers"
/* Permanent.     https://fetch.spec.whatwg.org/#http-access-control-allow-methods */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS \
  "Access-Control-Allow-Methods"
/* Permanent.     https://fetch.spec.whatwg.org/#http-access-control-allow-origin */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN \
  "Access-Control-Allow-Origin"
/* Permanent.     https://fetch.spec.whatwg.org/#http-access-control-expose-headers */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS \
  "Access-Control-Expose-Headers"
/* Permanent.     https://fetch.spec.whatwg.org/#http-access-control-max-age */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_MAX_AGE "Access-Control-Max-Age"
/* Permanent.     https://fetch.spec.whatwg.org/#http-access-control-request-headers */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_REQUEST_HEADERS \
  "Access-Control-Request-Headers"
/* Permanent.     https://fetch.spec.whatwg.org/#http-access-control-request-method */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_REQUEST_METHOD \
  "Access-Control-Request-Method"
/* Permanent.     RFC7639, Section 2 */
#define MHD_HTTP_HEADER_ALPN         "ALPN"
/* Permanent.     RFC7838 */
#define MHD_HTTP_HEADER_ALT_SVC      "Alt-Svc"
/* Permanent.     RFC7838 */
#define MHD_HTTP_HEADER_ALT_USED     "Alt-Used"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_ALTERNATES   "Alternates"
/* Permanent.     RFC4437 */
#define MHD_HTTP_HEADER_APPLY_TO_REDIRECT_REF "Apply-To-Redirect-Ref"
/* Permanent.     RFC8053, Section 4 */
#define MHD_HTTP_HEADER_AUTHENTICATION_CONTROL "Authentication-Control"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_C_EXT        "C-Ext"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_C_MAN        "C-Man"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_C_OPT        "C-Opt"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_C_PEP        "C-PEP"
/* Permanent.     RFC8607, Section 5.1 */
#define MHD_HTTP_HEADER_CAL_MANAGED_ID "Cal-Managed-ID"
/* Permanent.     RFC7809, Section 7.1 */
#define MHD_HTTP_HEADER_CALDAV_TIMEZONES "CalDAV-Timezones"
/* Permanent.     RFC8586 */
#define MHD_HTTP_HEADER_CDN_LOOP     "CDN-Loop"
/* Permanent.     RFC8739, Section 3.3 */
#define MHD_HTTP_HEADER_CERT_NOT_AFTER "Cert-Not-After"
/* Permanent.     RFC8739, Section 3.3 */
#define MHD_HTTP_HEADER_CERT_NOT_BEFORE "Cert-Not-Before"
/* Permanent.     RFC6266 */
#define MHD_HTTP_HEADER_CONTENT_DISPOSITION "Content-Disposition"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_CONTENT_ID   "Content-ID"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_CONTENT_SCRIPT_TYPE "Content-Script-Type"
/* Permanent.     https://www.w3.org/TR/CSP/#csp-header */
#define MHD_HTTP_HEADER_CONTENT_SECURITY_POLICY "Content-Security-Policy"
/* Permanent.     https://www.w3.org/TR/CSP/#cspro-header */
#define MHD_HTTP_HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY \
  "Content-Security-Policy-Report-Only"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_CONTENT_STYLE_TYPE "Content-Style-Type"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_CONTENT_VERSION "Content-Version"
/* Permanent.     RFC6265 */
#define MHD_HTTP_HEADER_COOKIE       "Cookie"
/* Permanent.     https://html.spec.whatwg.org/multipage/origin.html#cross-origin-embedder-policy */
#define MHD_HTTP_HEADER_CROSS_ORIGIN_EMBEDDER_POLICY \
  "Cross-Origin-Embedder-Policy"
/* Permanent.     https://html.spec.whatwg.org/multipage/origin.html#cross-origin-embedder-policy-report-only */
#define MHD_HTTP_HEADER_CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY \
  "Cross-Origin-Embedder-Policy-Report-Only"
/* Permanent.     https://html.spec.whatwg.org/multipage/origin.html#cross-origin-opener-policy-2 */
#define MHD_HTTP_HEADER_CROSS_ORIGIN_OPENER_POLICY "Cross-Origin-Opener-Policy"
/* Permanent.     https://html.spec.whatwg.org/multipage/origin.html#cross-origin-opener-policy-report-only */
#define MHD_HTTP_HEADER_CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY \
  "Cross-Origin-Opener-Policy-Report-Only"
/* Permanent.     https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header */
#define MHD_HTTP_HEADER_CROSS_ORIGIN_RESOURCE_POLICY \
  "Cross-Origin-Resource-Policy"
/* Permanent.     RFC5323 */
#define MHD_HTTP_HEADER_DASL         "DASL"
/* Permanent.     RFC4918 */
#define MHD_HTTP_HEADER_DAV          "DAV"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_DEFAULT_STYLE "Default-Style"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_DELTA_BASE   "Delta-Base"
/* Permanent.     RFC4918 */
#define MHD_HTTP_HEADER_DEPTH        "Depth"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_DERIVED_FROM "Derived-From"
/* Permanent.     RFC4918 */
#define MHD_HTTP_HEADER_DESTINATION  "Destination"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_DIFFERENTIAL_ID "Differential-ID"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_DIGEST       "Digest"
/* Permanent.     RFC8470 */
#define MHD_HTTP_HEADER_EARLY_DATA   "Early-Data"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_EXT          "Ext"
/* Permanent.     RFC7239 */
#define MHD_HTTP_HEADER_FORWARDED    "Forwarded"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_GETPROFILE   "GetProfile"
/* Permanent.     RFC7486, Section 6.1.1 */
#define MHD_HTTP_HEADER_HOBAREG      "Hobareg"
/* Permanent.     RFC7540, Section 3.2.1 */
#define MHD_HTTP_HEADER_HTTP2_SETTINGS "HTTP2-Settings"
/* Permanent.     RFC4918 */
#define MHD_HTTP_HEADER_IF           "If"
/* Permanent.     RFC6638 */
#define MHD_HTTP_HEADER_IF_SCHEDULE_TAG_MATCH "If-Schedule-Tag-Match"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_IM           "IM"
/* Permanent.     RFC8473 */
#define MHD_HTTP_HEADER_INCLUDE_REFERRED_TOKEN_BINDING_ID \
  "Include-Referred-Token-Binding-ID"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_KEEP_ALIVE   "Keep-Alive"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_LABEL        "Label"
/* Permanent.     https://html.spec.whatwg.org/multipage/server-sent-events.html#last-event-id */
#define MHD_HTTP_HEADER_LAST_EVENT_ID "Last-Event-ID"
/* Permanent.     RFC8288 */
#define MHD_HTTP_HEADER_LINK         "Link"
/* Permanent.     RFC4918 */
#define MHD_HTTP_HEADER_LOCK_TOKEN   "Lock-Token"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_MAN          "Man"
/* Permanent.     RFC7089 */
#define MHD_HTTP_HEADER_MEMENTO_DATETIME "Memento-Datetime"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_METER        "Meter"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_NEGOTIATE    "Negotiate"
/* Permanent.     OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_ODATA_ENTITYID "OData-EntityId"
/* Permanent.     OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_ODATA_ISOLATION "OData-Isolation"
/* Permanent.     OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_ODATA_MAXVERSION "OData-MaxVersion"
/* Permanent.     OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_ODATA_VERSION "OData-Version"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_OPT          "Opt"
/* Permanent.     RFC8053, Section 3 */
#define MHD_HTTP_HEADER_OPTIONAL_WWW_AUTHENTICATE "Optional-WWW-Authenticate"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_ORDERING_TYPE "Ordering-Type"
/* Permanent.     RFC6454 */
#define MHD_HTTP_HEADER_ORIGIN       "Origin"
/* Permanent.     https://html.spec.whatwg.org/multipage/origin.html#origin-agent-cluster */
#define MHD_HTTP_HEADER_ORIGIN_AGENT_CLUSTER "Origin-Agent-Cluster"
/* Permanent.     RFC8613, Section 11.1 */
#define MHD_HTTP_HEADER_OSCORE       "OSCORE"
/* Permanent.     OASIS Project Specification 01; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_OSLC_CORE_VERSION "OSLC-Core-Version"
/* Permanent.     RFC4918 */
#define MHD_HTTP_HEADER_OVERWRITE    "Overwrite"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_P3P          "P3P"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_PEP          "PEP"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_PEP_INFO     "Pep-Info"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_PICS_LABEL   "PICS-Label"
/* Permanent.     https://html.spec.whatwg.org/multipage/links.html#ping-from */
#define MHD_HTTP_HEADER_PING_FROM    "Ping-From"
/* Permanent.     https://html.spec.whatwg.org/multipage/links.html#ping-to */
#define MHD_HTTP_HEADER_PING_TO      "Ping-To"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_POSITION     "Position"
/* Permanent.     RFC7240 */
#define MHD_HTTP_HEADER_PREFER       "Prefer"
/* Permanent.     RFC7240 */
#define MHD_HTTP_HEADER_PREFERENCE_APPLIED "Preference-Applied"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_PROFILEOBJECT "ProfileObject"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_PROTOCOL     "Protocol"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_PROTOCOL_REQUEST "Protocol-Request"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_PROXY_FEATURES "Proxy-Features"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_PROXY_INSTRUCTION "Proxy-Instruction"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_PUBLIC       "Public"
/* Permanent.     RFC7469 */
#define MHD_HTTP_HEADER_PUBLIC_KEY_PINS "Public-Key-Pins"
/* Permanent.     RFC7469 */
#define MHD_HTTP_HEADER_PUBLIC_KEY_PINS_REPORT_ONLY \
  "Public-Key-Pins-Report-Only"
/* Permanent.     RFC4437 */
#define MHD_HTTP_HEADER_REDIRECT_REF "Redirect-Ref"
/* Permanent.     https://html.spec.whatwg.org/multipage/browsing-the-web.html#refresh */
#define MHD_HTTP_HEADER_REFRESH      "Refresh"
/* Permanent.     RFC8555, Section 6.5.1 */
#define MHD_HTTP_HEADER_REPLAY_NONCE "Replay-Nonce"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_SAFE         "Safe"
/* Permanent.     RFC6638 */
#define MHD_HTTP_HEADER_SCHEDULE_REPLY "Schedule-Reply"
/* Permanent.     RFC6638 */
#define MHD_HTTP_HEADER_SCHEDULE_TAG "Schedule-Tag"
/* Permanent.     RFC8473 */
#define MHD_HTTP_HEADER_SEC_TOKEN_BINDING "Sec-Token-Binding"
/* Permanent.     RFC6455 */
#define MHD_HTTP_HEADER_SEC_WEBSOCKET_ACCEPT "Sec-WebSocket-Accept"
/* Permanent.     RFC6455 */
#define MHD_HTTP_HEADER_SEC_WEBSOCKET_EXTENSIONS "Sec-WebSocket-Extensions"
/* Permanent.     RFC6455 */
#define MHD_HTTP_HEADER_SEC_WEBSOCKET_KEY "Sec-WebSocket-Key"
/* Permanent.     RFC6455 */
#define MHD_HTTP_HEADER_SEC_WEBSOCKET_PROTOCOL "Sec-WebSocket-Protocol"
/* Permanent.     RFC6455 */
#define MHD_HTTP_HEADER_SEC_WEBSOCKET_VERSION "Sec-WebSocket-Version"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_SECURITY_SCHEME "Security-Scheme"
/* Permanent.     https://www.w3.org/TR/server-timing/ */
#define MHD_HTTP_HEADER_SERVER_TIMING "Server-Timing"
/* Permanent.     RFC6265 */
#define MHD_HTTP_HEADER_SET_COOKIE   "Set-Cookie"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_SETPROFILE   "SetProfile"
/* Permanent.     RFC5023 */
#define MHD_HTTP_HEADER_SLUG         "SLUG"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_SOAPACTION   "SoapAction"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_STATUS_URI   "Status-URI"
/* Permanent.     RFC6797 */
#define MHD_HTTP_HEADER_STRICT_TRANSPORT_SECURITY "Strict-Transport-Security"
/* Permanent.     RFC8594 */
#define MHD_HTTP_HEADER_SUNSET       "Sunset"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_SURROGATE_CAPABILITY "Surrogate-Capability"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_SURROGATE_CONTROL "Surrogate-Control"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_TCN          "TCN"
/* Permanent.     RFC4918 */
#define MHD_HTTP_HEADER_TIMEOUT      "Timeout"
/* Permanent.     RFC8030, Section 5.4 */
#define MHD_HTTP_HEADER_TOPIC        "Topic"
/* Permanent.     RFC8030, Section 5.2 */
#define MHD_HTTP_HEADER_TTL          "TTL"
/* Permanent.     RFC8030, Section 5.3 */
#define MHD_HTTP_HEADER_URGENCY      "Urgency"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_URI          "URI"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_VARIANT_VARY "Variant-Vary"
/* Permanent.     RFC4229 */
#define MHD_HTTP_HEADER_WANT_DIGEST  "Want-Digest"
/* Permanent.     https://fetch.spec.whatwg.org/#x-content-type-options-header */
#define MHD_HTTP_HEADER_X_CONTENT_TYPE_OPTIONS "X-Content-Type-Options"
/* Permanent.     https://html.spec.whatwg.org/multipage/browsing-the-web.html#x-frame-options */
#define MHD_HTTP_HEADER_X_FRAME_OPTIONS "X-Frame-Options"
/* Provisional.   RFC5789 */
#define MHD_HTTP_HEADER_ACCEPT_PATCH "Accept-Patch"
/* Provisional.   https://github.com/ampproject/amphtml/blob/master/spec/amp-cache-transform.md */
#define MHD_HTTP_HEADER_AMP_CACHE_TRANSFORM "AMP-Cache-Transform"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_COMPLIANCE   "Compliance"
/* Provisional.   https://docs.oasis-open-projects.org/oslc-op/config/v1.0/psd01/config-resources.html#configcontext */
#define MHD_HTTP_HEADER_CONFIGURATION_CONTEXT "Configuration-Context"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_CONTENT_TRANSFER_ENCODING "Content-Transfer-Encoding"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_COST         "Cost"
/* Provisional.   RFC6017 */
#define MHD_HTTP_HEADER_EDIINT_FEATURES "EDIINT-Features"
/* Provisional.   OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_ISOLATION    "Isolation"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_MESSAGE_ID   "Message-ID"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_NON_COMPLIANCE "Non-Compliance"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_OPTIONAL     "Optional"
/* Provisional.   Repeatable Requests Version 1.0; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_REPEATABILITY_CLIENT_ID "Repeatability-Client-ID"
/* Provisional.   Repeatable Requests Version 1.0; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_REPEATABILITY_FIRST_SENT "Repeatability-First-Sent"
/* Provisional.   Repeatable Requests Version 1.0; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_REPEATABILITY_REQUEST_ID "Repeatability-Request-ID"
/* Provisional.   Repeatable Requests Version 1.0; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_REPEATABILITY_RESULT "Repeatability-Result"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_RESOLUTION_HINT "Resolution-Hint"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_RESOLVER_LOCATION "Resolver-Location"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_SUBOK        "SubOK"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_SUBST        "Subst"
/* Provisional.   https://www.w3.org/TR/resource-timing-1/#timing-allow-origin */
#define MHD_HTTP_HEADER_TIMING_ALLOW_ORIGIN "Timing-Allow-Origin"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_TITLE        "Title"
/* Provisional.   https://www.w3.org/TR/trace-context/#traceparent-field */
#define MHD_HTTP_HEADER_TRACEPARENT  "Traceparent"
/* Provisional.   https://www.w3.org/TR/trace-context/#tracestate-field */
#define MHD_HTTP_HEADER_TRACESTATE   "Tracestate"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_UA_COLOR     "UA-Color"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_UA_MEDIA     "UA-Media"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_UA_PIXELS    "UA-Pixels"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_UA_RESOLUTION "UA-Resolution"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_UA_WINDOWPIXELS "UA-Windowpixels"
/* Provisional.   RFC4229 */
#define MHD_HTTP_HEADER_VERSION      "Version"
/* Provisional.   W3C Mobile Web Best Practices Working Group */
#define MHD_HTTP_HEADER_X_DEVICE_ACCEPT "X-Device-Accept"
/* Provisional.   W3C Mobile Web Best Practices Working Group */
#define MHD_HTTP_HEADER_X_DEVICE_ACCEPT_CHARSET "X-Device-Accept-Charset"
/* Provisional.   W3C Mobile Web Best Practices Working Group */
#define MHD_HTTP_HEADER_X_DEVICE_ACCEPT_ENCODING "X-Device-Accept-Encoding"
/* Provisional.   W3C Mobile Web Best Practices Working Group */
#define MHD_HTTP_HEADER_X_DEVICE_ACCEPT_LANGUAGE "X-Device-Accept-Language"
/* Provisional.   W3C Mobile Web Best Practices Working Group */
#define MHD_HTTP_HEADER_X_DEVICE_USER_AGENT "X-Device-User-Agent"
/* Deprecated.    RFC4229 */
#define MHD_HTTP_HEADER_C_PEP_INFO   "C-PEP-Info"
/* Deprecated.    RFC4229 */
#define MHD_HTTP_HEADER_PROTOCOL_INFO "Protocol-Info"
/* Deprecated.    RFC4229 */
#define MHD_HTTP_HEADER_PROTOCOL_QUERY "Protocol-Query"
/* Obsoleted.     https://www.w3.org/TR/2007/WD-access-control-20071126/#access-control0 */
#define MHD_HTTP_HEADER_ACCESS_CONTROL "Access-Control"
/* Obsoleted.     RFC2068; RFC2616 */
#define MHD_HTTP_HEADER_CONTENT_BASE "Content-Base"
/* Obsoleted.     RFC2616, Section 14.15; RFC7231, Appendix B */
#define MHD_HTTP_HEADER_CONTENT_MD5  "Content-MD5"
/* Obsoleted.     RFC2965; RFC6265 */
#define MHD_HTTP_HEADER_COOKIE2      "Cookie2"
/* Obsoleted.     https://www.w3.org/TR/2007/WD-access-control-20071126/#method-check */
#define MHD_HTTP_HEADER_METHOD_CHECK "Method-Check"
/* Obsoleted.     https://www.w3.org/TR/2007/WD-access-control-20071126/#method-check-expires */
#define MHD_HTTP_HEADER_METHOD_CHECK_EXPIRES "Method-Check-Expires"
/* Obsoleted.     https://www.w3.org/TR/2007/WD-access-control-20071126/#referer-root */
#define MHD_HTTP_HEADER_REFERER_ROOT "Referer-Root"
/* Obsoleted.     RFC2965; RFC6265 */
#define MHD_HTTP_HEADER_SET_COOKIE2  "Set-Cookie2"

/* Some provisional headers. */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN \
  "Access-Control-Allow-Origin"
/** @} */ /* end of group headers */

/**
 * Operational results from MHD calls.
 */
enum MHD_Result
{
  /**
   * MHD result code for "NO".
   */
  MHD_NO = 0,

  /**
   * MHD result code for "YES".
   */
  MHD_YES = 1

};

enum SCEP_OPERATION
{
	GetCAcaps = 1,
	GetCACert,
	PKIOperation,
	SaveConf
};

/*
 * Structures
 */
struct httpd;

typedef struct _HTTPParameters
{
    char                    Uri[1024];
    char                    ProxyHost[1024];
    uint32_t                UseProxy ;
    uint32_t                ProxyPort;
    uint32_t                Verbose;
} HTTPParameters;

struct context {
	const char *challenge_password;	// challenge password to compare
    long allow_renew_days;			// allow to renew days
    long validity_days;				// Validity of the certificate in days
    long offset_days;				// offset to apply to the current date (in days)
    const char *depot;				// not used
    struct scep *scep;
};

/* Returns HTTP status code (like 200) */
//typedef unsigned int (*httpd_handler_t)(
//        void * /* context */,
//        const char * /* operation */,
//        BIO * /* payload */,
//        const char ** /* response content type, statically allocated */,
//        BIO * /* response (can be binary), or redirect URL (zero terminated) */
//        );

//extern struct httpd *httpd_new(
//        uint16_t port,
//        httpd_handler_t handler,
//        void *context);

//extern int httpd_start(struct httpd *httpd);
//extern int httpd_poll(struct httpd *httpd, sigset_t *sigset);
//extern int httpd_stop(struct httpd *httpd);
//extern void httpd_free(struct httpd *httpd);
void httpd_hello(int number);

int32_t http_uri_decode(HTTPParameters *pClientParams);
enum MHD_Result httpd_handler(
        //void *cls,
        //struct MHD_Connection *connection,
		struct context *context,
        const char *url,
        const char *method,
        //const char *version,
        //const char *upload_data,
        size_t *upload_data_size
        //void **con_cls
		);

// this function is in main.c
unsigned int handle(
		struct context *context,
        const char *operation,
        BIO *payload,
        const char **rct,
        BIO *response,
		int32_t *scep_operation);

#endif /* SCEP_HTTPD_H */
