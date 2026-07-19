package adminapi

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/adminstore"
)

var (
	_ AuthenticationBoundary               = (*adminauth.Boundary)(nil)
	_ SessionStore                         = (*adminstore.PostgreSQLStore)(nil)
	_ HistoricalDecisionReplayBoundary     = (*adminauth.Boundary)(nil)
	_ HistoricalDecisionReplaySessionStore = (*adminstore.PostgreSQLStore)(nil)
)

type requestFailure struct {
	status     int
	code       ErrorCode
	retryAfter time.Duration
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setCommonHeaders(writer)
	if handler == nil || handler.boundary == nil || handler.sessions == nil {
		writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
		return
	}
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		writeError(writer, http.StatusNotFound, ErrorNotFound, 0)
		return
	}
	if actionID, route, ok := parseRevocationPath(request.URL.Path); ok {
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, http.MethodPost)
			return
		}
		if !validPOSTEnvelopeWithLimit(request, MaxHILRequestBodyBytes) {
			writeError(writer, http.StatusBadRequest, ErrorSchemaInvalid, 0)
			return
		}
		if handler.revocations == nil {
			writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
			return
		}
		switch route {
		case revocationChallengeRoute:
			handler.BrowserMutationMiddleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				handler.serveRevocationChallenge(writer, request, actionID)
			})).ServeHTTP(writer, request)
		case revocationDecisionRoute:
			handler.policyDecisionMutationMiddleware(
				http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					handler.serveRevocationDecision(writer, request, actionID)
				}),
				http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					handler.serveHistoricalRevocationReplay(writer, request, actionID)
				}),
			).ServeHTTP(writer, request)
		default:
			writeError(writer, http.StatusNotFound, ErrorNotFound, 0)
		}
		return
	}
	if policyID, route, ok := parsePolicyHILPath(request.URL.Path); ok {
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, http.MethodPost)
			return
		}
		if !validPOSTEnvelopeWithLimit(request, MaxHILRequestBodyBytes) {
			writeError(writer, http.StatusBadRequest, ErrorSchemaInvalid, 0)
			return
		}
		if handler.exactArtifacts == nil || handler.hil == nil {
			writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
			return
		}
		switch route {
		case policyHILChallengeRoute:
			handler.BrowserMutationMiddleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				handler.servePolicyDecisionChallenge(writer, request, policyID)
			})).ServeHTTP(writer, request)
		case policyHILDecisionRoute:
			handler.policyDecisionMutationMiddleware(
				http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					handler.servePolicyDecision(writer, request, policyID)
				}),
				http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					handler.serveHistoricalPolicyDecisionReplay(writer, request, policyID)
				}),
			).ServeHTTP(writer, request)
		default:
			writeError(writer, http.StatusNotFound, ErrorNotFound, 0)
		}
		return
	}
	switch request.URL.Path {
	case LoginPath:
		handler.serveLogin(writer, request)
	case LogoutPath:
		handler.serveLogout(writer, request)
	case StepUpPath:
		handler.serveStepUp(writer, request)
	case SessionPath:
		handler.serveSession(writer, request)
	default:
		writeError(writer, http.StatusNotFound, ErrorNotFound, 0)
	}
}

func (handler *Handler) serveLogin(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	if !validPOSTEnvelope(request) {
		writeError(writer, http.StatusBadRequest, ErrorSchemaInvalid, 0)
		return
	}
	source, ok := canonicalDirectPeer(request.RemoteAddr)
	if !ok {
		writeError(writer, http.StatusBadRequest, ErrorSchemaInvalid, 0)
		return
	}
	if _, failure := handler.requireOrigin(request); failure != nil {
		writeFailure(writer, *failure)
		return
	}
	input, err := decodeLogin(request)
	if err != nil {
		writeError(writer, http.StatusBadRequest, ErrorSchemaInvalid, 0)
		return
	}
	defer clear(input.password)
	issued, err := handler.boundary.Login(source, input.username, input.password)
	if err != nil {
		writeFailure(writer, authenticationFailure(err))
		return
	}
	defer issued.ClearSecrets()
	persisted, err := handler.sessions.InsertLogin(request.Context(), issued.Record)
	if err != nil {
		writeFailure(writer, storeFailure(err, false))
		return
	}
	if !sameSessionRecord(persisted, issued.Record) {
		writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
		return
	}
	cookie, err := handler.cookies.IssuedSessionCookie(issued)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
		return
	}
	csrfToken := issued.CSRFToken()
	http.SetCookie(writer, cookie)
	writeJSON(writer, http.StatusOK, sessionEnvelope{Session: project(persisted), CSRFToken: csrfToken})
}

func (handler *Handler) serveSession(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if !validGETEnvelope(request) {
		writeError(writer, http.StatusBadRequest, ErrorSchemaInvalid, 0)
		return
	}
	if _, ok := canonicalDirectPeer(request.RemoteAddr); !ok {
		writeError(writer, http.StatusBadRequest, ErrorSchemaInvalid, 0)
		return
	}
	record, credential, failure := handler.authenticateRead(request)
	if failure != nil {
		writeFailure(writer, *failure)
		return
	}
	csrfToken, err := handler.boundary.RecoverCSRFToken(record, credential.PresentedToken())
	if err != nil {
		writeFailure(writer, authenticationFailure(err))
		return
	}
	writeJSON(writer, http.StatusOK, sessionEnvelope{Session: project(record), CSRFToken: csrfToken})
}

func (handler *Handler) serveLogout(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	if !validPOSTEnvelope(request) {
		writeError(writer, http.StatusBadRequest, ErrorSchemaInvalid, 0)
		return
	}
	if _, ok := canonicalDirectPeer(request.RemoteAddr); !ok {
		writeError(writer, http.StatusBadRequest, ErrorSchemaInvalid, 0)
		return
	}
	origin, failure := handler.requireOrigin(request)
	if failure != nil {
		writeFailure(writer, *failure)
		return
	}
	if err := decodeEmptyObject(request); err != nil {
		writeError(writer, http.StatusBadRequest, ErrorSchemaInvalid, 0)
		return
	}
	record, _, failure := handler.authenticateMutation(request, origin)
	if failure != nil {
		writeFailure(writer, *failure)
		return
	}
	if _, err := handler.sessions.Revoke(request.Context(), record); err != nil {
		writeFailure(writer, storeFailure(err, false))
		return
	}
	http.SetCookie(writer, handler.cookies.ExpiredCookie())
	writer.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) serveStepUp(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	if !validPOSTEnvelope(request) {
		writeError(writer, http.StatusBadRequest, ErrorSchemaInvalid, 0)
		return
	}
	if _, ok := canonicalDirectPeer(request.RemoteAddr); !ok {
		writeError(writer, http.StatusBadRequest, ErrorSchemaInvalid, 0)
		return
	}
	origin, failure := handler.requireOrigin(request)
	if failure != nil {
		writeFailure(writer, *failure)
		return
	}
	input, err := decodeStepUp(request)
	if err != nil {
		writeError(writer, http.StatusBadRequest, ErrorSchemaInvalid, 0)
		return
	}
	defer clear(input.password)
	record, credential, failure := handler.authenticateMutation(request, origin)
	if failure != nil {
		writeFailure(writer, *failure)
		return
	}
	rotation, err := handler.boundary.StepUp(record, credential.PresentedToken(), input.password)
	if err != nil {
		writeFailure(writer, authenticationFailure(err))
		return
	}
	defer rotation.ClearSecrets()
	persisted, err := handler.sessions.Rotate(request.Context(), record, rotation.Issued.Record)
	if err != nil {
		writeFailure(writer, storeFailure(err, false))
		return
	}
	if !sameSessionRecord(persisted, rotation.Issued.Record) {
		writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
		return
	}
	cookie, err := handler.cookies.IssuedSessionCookie(rotation.Issued)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
		return
	}
	csrfToken := rotation.Issued.CSRFToken()
	http.SetCookie(writer, cookie)
	writeJSON(writer, http.StatusOK, sessionEnvelope{Session: project(persisted), CSRFToken: csrfToken})
}

func (handler *Handler) requireOrigin(request *http.Request) (string, *requestFailure) {
	values := request.Header.Values("Origin")
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 512 || handler.boundary.ValidateOrigin(values[0]) != nil {
		failure := requestFailure{status: http.StatusForbidden, code: ErrorPermissionDenied}
		return "", &failure
	}
	return values[0], nil
}

func (handler *Handler) authenticateRead(request *http.Request) (adminauth.SessionRecord, adminauth.SessionCookieCredential, *requestFailure) {
	credential, err := handler.cookies.ReadSessionCredential(request)
	if err != nil {
		failure := requestFailure{status: http.StatusUnauthorized, code: ErrorAuthenticationRequired}
		return adminauth.SessionRecord{}, adminauth.SessionCookieCredential{}, &failure
	}
	loaded, err := handler.sessions.LoadByID(request.Context(), credential.SessionID())
	if err != nil {
		failure := storeFailure(err, true)
		return adminauth.SessionRecord{}, adminauth.SessionCookieCredential{}, &failure
	}
	if _, err := handler.boundary.ValidateSession(loaded, credential.PresentedToken()); err != nil {
		failure := requestFailure{status: http.StatusUnauthorized, code: ErrorAuthenticationRequired}
		return adminauth.SessionRecord{}, adminauth.SessionCookieCredential{}, &failure
	}
	touched, err := handler.sessions.Touch(request.Context(), loaded)
	if err != nil {
		failure := storeFailure(err, false)
		return adminauth.SessionRecord{}, adminauth.SessionCookieCredential{}, &failure
	}
	return touched, credential, nil
}

func (handler *Handler) authenticateMutation(request *http.Request, origin string) (adminauth.SessionRecord, adminauth.SessionCookieCredential, *requestFailure) {
	credential, err := handler.cookies.ReadSessionCredential(request)
	if err != nil {
		failure := requestFailure{status: http.StatusUnauthorized, code: ErrorAuthenticationRequired}
		return adminauth.SessionRecord{}, adminauth.SessionCookieCredential{}, &failure
	}
	loaded, err := handler.sessions.LoadByID(request.Context(), credential.SessionID())
	if err != nil {
		failure := storeFailure(err, true)
		return adminauth.SessionRecord{}, adminauth.SessionCookieCredential{}, &failure
	}
	if _, err := handler.boundary.ValidateSession(loaded, credential.PresentedToken()); err != nil {
		failure := requestFailure{status: http.StatusUnauthorized, code: ErrorAuthenticationRequired}
		return adminauth.SessionRecord{}, adminauth.SessionCookieCredential{}, &failure
	}
	csrfValues := request.Header.Values("X-CSRF-Token")
	if len(csrfValues) != 1 || len(csrfValues[0]) == 0 || len(csrfValues[0]) > 128 {
		failure := requestFailure{status: http.StatusForbidden, code: ErrorCSRFInvalid}
		return adminauth.SessionRecord{}, adminauth.SessionCookieCredential{}, &failure
	}
	if _, err := handler.boundary.ValidateBrowserRequest(loaded, credential.PresentedToken(), csrfValues[0], origin); err != nil {
		failure := requestFailure{status: http.StatusForbidden, code: ErrorCSRFInvalid}
		return adminauth.SessionRecord{}, adminauth.SessionCookieCredential{}, &failure
	}
	return loaded, credential, nil
}

func authenticationFailure(err error) requestFailure {
	var limited *adminauth.RateLimitError
	if errors.As(err, &limited) {
		return requestFailure{status: http.StatusTooManyRequests, code: ErrorRateLimited, retryAfter: limited.RetryAfter}
	}
	if errors.Is(err, adminauth.ErrInvalidCredentials) {
		return requestFailure{status: http.StatusUnauthorized, code: ErrorAuthenticationRequired}
	}
	if errors.Is(err, adminauth.ErrSessionInvalid) {
		return requestFailure{status: http.StatusUnauthorized, code: ErrorAuthenticationRequired}
	}
	return requestFailure{status: http.StatusServiceUnavailable, code: ErrorServiceUnavailable}
}

func storeFailure(err error, missingIsUnauthorized bool) requestFailure {
	if errors.Is(err, adminstore.ErrNotFound) && missingIsUnauthorized {
		return requestFailure{status: http.StatusUnauthorized, code: ErrorAuthenticationRequired}
	}
	if errors.Is(err, adminstore.ErrConflict) || errors.Is(err, adminstore.ErrNotFound) {
		return requestFailure{status: http.StatusConflict, code: ErrorStaleVersion}
	}
	return requestFailure{status: http.StatusServiceUnavailable, code: ErrorServiceUnavailable}
}

func writeFailure(writer http.ResponseWriter, failure requestFailure) {
	writeError(writer, failure.status, failure.code, failure.retryAfter)
}

func methodNotAllowed(writer http.ResponseWriter, method string) {
	writer.Header().Set("Allow", method)
	writeError(writer, http.StatusMethodNotAllowed, ErrorSchemaInvalid, 0)
}

func canonicalDirectPeer(remoteAddress string) (netip.Addr, bool) {
	host, portText, err := net.SplitHostPort(remoteAddress)
	if err != nil || host == "" || portText == "" || len(portText) > 5 || portText[0] == '0' {
		return netip.Addr{}, false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != portText {
		return netip.Addr{}, false
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsValid() || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() ||
		address.String() != host || net.JoinHostPort(host, portText) != remoteAddress {
		return netip.Addr{}, false
	}
	return address, true
}

func sameSessionRecord(left, right adminauth.SessionRecord) bool {
	return left.ID == right.ID && left.ActorID == right.ActorID && left.TokenDigest == right.TokenDigest &&
		left.CSRFDigest == right.CSRFDigest && left.AuthenticatedAt.Equal(right.AuthenticatedAt) &&
		left.CreatedAt.Equal(right.CreatedAt) && left.LastSeenAt.Equal(right.LastSeenAt) &&
		left.ExpiresAt.Equal(right.ExpiresAt) && sameOptionalTime(left.RevokedAt, right.RevokedAt) &&
		sameOptionalID(left.RotationParentID, right.RotationParentID)
}

func sameOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func sameOptionalID(left, right *adminauth.SessionID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
