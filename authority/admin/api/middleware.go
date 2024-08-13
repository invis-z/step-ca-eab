package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
)

// requireAPIEnabled is a middleware that ensures the Administration API
// is enabled before servicing requests.
func requireAPIEnabled(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !mustAuthority(r.Context()).IsAdminAPIEnabled() {
			render.Error(w, r, admin.NewError(admin.ErrorNotImplementedType, "administration API not enabled"))
			return
		}
		next(w, r)
	}
}

// extractAuthorizeTokenAdmin is a middleware that extracts and caches the bearer token.
func extractAuthorizeTokenAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("Authorization")
		if tok == "" {
			render.Error(w, r, admin.NewError(admin.ErrorUnauthorizedType,
				"missing authorization header token"))
			return
		}

		ctx := r.Context()
		adm, err := mustAuthority(ctx).AuthorizeAdminToken(r, tok)
		if err != nil {
			render.Error(w, r, err)
			return
		}

		ctx = linkedca.NewContextWithAdmin(ctx, adm)
		next(w, r.WithContext(ctx))
	}
}

// loadProvisionerByName is a middleware that searches for a provisioner
// by name and stores it in the context.
func loadProvisionerByName(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			p   provisioner.Interface
			err error
		)

		ctx := r.Context()
		auth := mustAuthority(ctx)
		adminDB := admin.MustFromContext(ctx)
		name := chi.URLParam(r, "provisionerName")

		// TODO(hs): distinguish 404 vs. 500
		if p, err = auth.LoadProvisionerByName(name); err != nil {
			render.Error(w, r, admin.WrapErrorISE(err, "error loading provisioner %s", name))
			return
		}

		prov, err := adminDB.GetProvisioner(ctx, p.GetID())
		if err != nil {
			render.Error(w, r, admin.WrapErrorISE(err, "error retrieving provisioner %s", name))
			return
		}

		ctx = linkedca.NewContextWithProvisioner(ctx, prov)
		next(w, r.WithContext(ctx))
	}
}

// loadExternalAccountKey is a middleware that searches for an ACME
// External Account Key by reference or keyID and stores it in the context.
func loadExternalAccountKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		prov := linkedca.MustProvisionerFromContext(ctx)
		acmeDB := acme.MustDatabaseFromContext(ctx)

		reference := chi.URLParam(r, "reference")
		keyID := chi.URLParam(r, "keyID")

		var (
			eak *acme.ExternalAccountKey
			err error
		)

		if keyID != "" {
			eak, err = acmeDB.GetExternalAccountKey(ctx, prov.GetId(), keyID)
		} else {
			eak, err = acmeDB.GetExternalAccountKeyByReference(ctx, prov.GetId(), reference)
		}

		if err != nil {
			if acme.IsErrNotFound(err) {
				render.Error(w, r, admin.NewError(admin.ErrorNotFoundType, "ACME External Account Key not found"))
				return
			}
			render.Error(w, r, admin.WrapErrorISE(err, "error retrieving ACME External Account Key"))
			return
		}

		if eak == nil {
			render.Error(w, r, admin.NewError(admin.ErrorNotFoundType, "ACME External Account Key not found"))
			return
		}

		linkedEAK := eakToLinked(eak)

		ctx = linkedca.NewContextWithExternalAccountKey(ctx, linkedEAK)

		next(w, r.WithContext(ctx))
	}
}
