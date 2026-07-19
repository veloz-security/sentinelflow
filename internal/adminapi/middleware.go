package adminapi

import (
	"errors"
	"net/http"

	"github.com/devwooops/sentinelflow/internal/adminstore"
)

// SessionMiddleware validates the current cookie, exact-CAS touches the
// database row using the database clock, and places only a safe public
// projection plus a package-private browser credential in context.
func (handler *Handler) SessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		setCommonHeaders(writer)
		if handler == nil || next == nil || request == nil {
			writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
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
		bound, clearToken := withAuthenticatedBrowser(request, record, credential.PresentedToken())
		defer clearToken()
		next.ServeHTTP(writer, bound)
	})
}

// BrowserMutationMiddleware adds exact Origin and synchronizer-CSRF checks
// before the database-clock Touch. Future HIL handlers in this package can use
// authenticatedFromContext to bind an exact touched row and presented token.
func (handler *Handler) BrowserMutationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		setCommonHeaders(writer)
		if handler == nil || next == nil || request == nil {
			writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
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
		loaded, credential, failure := handler.authenticateMutation(request, origin)
		if failure != nil {
			writeFailure(writer, *failure)
			return
		}
		touched, err := handler.sessions.Touch(request.Context(), loaded)
		if err != nil {
			writeFailure(writer, storeFailure(err, false))
			return
		}
		bound, clearToken := withAuthenticatedBrowser(request, touched, credential.PresentedToken())
		defer clearToken()
		next.ServeHTTP(writer, bound)
	})
}

// policyDecisionMutationMiddleware is the only browser boundary that admits a
// revoked session, and then only through the read-only replay handler. A live
// session follows the ordinary validate+Touch path. A missing live session may
// fall back only when persistence proves one recent, unique, still-live
// rotation child and the boundary authenticates the old bearer, CSRF, and
// exact Origin again.
func (handler *Handler) policyDecisionMutationMiddleware(next, replay http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		setCommonHeaders(writer)
		if handler == nil || next == nil || replay == nil || request == nil {
			writeError(writer, http.StatusServiceUnavailable, ErrorServiceUnavailable, 0)
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
		credential, err := handler.cookies.ReadSessionCredential(request)
		if err != nil {
			writeError(writer, http.StatusUnauthorized, ErrorAuthenticationRequired, 0)
			return
		}
		csrfValues := request.Header.Values("X-CSRF-Token")
		if len(csrfValues) != 1 || len(csrfValues[0]) == 0 || len(csrfValues[0]) > 128 {
			writeError(writer, http.StatusForbidden, ErrorCSRFInvalid, 0)
			return
		}

		loaded, loadErr := handler.sessions.LoadByID(request.Context(), credential.SessionID())
		if loadErr == nil {
			if _, err := handler.boundary.ValidateSession(loaded, credential.PresentedToken()); err != nil {
				writeError(writer, http.StatusUnauthorized, ErrorAuthenticationRequired, 0)
				return
			}
			if _, err := handler.boundary.ValidateBrowserRequest(loaded, credential.PresentedToken(), csrfValues[0], origin); err != nil {
				writeError(writer, http.StatusForbidden, ErrorCSRFInvalid, 0)
				return
			}
			touched, err := handler.sessions.Touch(request.Context(), loaded)
			if err != nil {
				writeFailure(writer, storeFailure(err, false))
				return
			}
			bound, clearToken := withAuthenticatedBrowser(request, touched, credential.PresentedToken())
			defer clearToken()
			next.ServeHTTP(writer, bound)
			return
		}
		if !errors.Is(loadErr, adminstore.ErrNotFound) {
			writeFailure(writer, storeFailure(loadErr, true))
			return
		}
		replayStore, storeOK := handler.sessions.(HistoricalDecisionReplaySessionStore)
		replayBoundary, boundaryOK := handler.boundary.(HistoricalDecisionReplayBoundary)
		if !storeOK || !boundaryOK {
			writeError(writer, http.StatusUnauthorized, ErrorAuthenticationRequired, 0)
			return
		}
		revoked, err := replayStore.LoadRevokedDecisionReplayParent(request.Context(), credential.SessionID())
		if err != nil {
			writeFailure(writer, storeFailure(err, true))
			return
		}
		validated, err := replayBoundary.ValidateRevokedBrowserReplay(
			revoked, credential.PresentedToken(), csrfValues[0], origin,
		)
		if err != nil || validated.RevokedAt == nil || validated.ID != revoked.ID {
			writeError(writer, http.StatusForbidden, ErrorCSRFInvalid, 0)
			return
		}
		bound, clearToken := withAuthenticatedBrowser(request, validated, credential.PresentedToken())
		defer clearToken()
		replay.ServeHTTP(writer, bound)
	})
}
