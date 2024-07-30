package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"go.step.sm/linkedca"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/authority/admin"
)

func readProtoJSON(r io.ReadCloser, m proto.Message) error {
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return protojson.Unmarshal(data, m)
}

func mockMustAuthority(t *testing.T, a adminAuthority) {
	t.Helper()
	fn := mustAuthority
	t.Cleanup(func() {
		mustAuthority = fn
	})
	mustAuthority = func(ctx context.Context) adminAuthority {
		return a
	}
}

func TestHandler_requireEABEnabled(t *testing.T) {
	type test struct {
		ctx        context.Context
		next       http.HandlerFunc
		err        *admin.Error
		statusCode int
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/prov.GetDetails": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id:   "provID",
				Name: "provName",
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			err := admin.NewErrorISE("error getting ACME details for provisioner 'provName'")
			err.Message = "error getting ACME details for provisioner 'provName'"
			return test{
				ctx:        ctx,
				err:        err,
				statusCode: 500,
			}
		},
		"fail/prov.GetDetails.GetACME": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id:      "provID",
				Name:    "provName",
				Details: &linkedca.ProvisionerDetails{},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			err := admin.NewErrorISE("error getting ACME details for provisioner 'provName'")
			err.Message = "error getting ACME details for provisioner 'provName'"
			return test{
				ctx:        ctx,
				err:        err,
				statusCode: 500,
			}
		},
		"ok/eab-disabled": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id:   "provID",
				Name: "provName",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_ACME{
						ACME: &linkedca.ACMEProvisioner{
							RequireEab: false,
						},
					},
				},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			err := admin.NewError(admin.ErrorBadRequestType, "ACME EAB not enabled for provisioner provName")
			err.Message = "ACME EAB not enabled for provisioner 'provName'"
			return test{
				ctx:        ctx,
				err:        err,
				statusCode: 400,
			}
		},
		"ok/eab-enabled": func(t *testing.T) test {
			prov := &linkedca.Provisioner{
				Id:   "provID",
				Name: "provName",
				Details: &linkedca.ProvisionerDetails{
					Data: &linkedca.ProvisionerDetails_ACME{
						ACME: &linkedca.ACMEProvisioner{
							RequireEab: true,
						},
					},
				},
			}
			ctx := linkedca.NewContextWithProvisioner(context.Background(), prov)
			return test{
				ctx: ctx,
				next: func(w http.ResponseWriter, r *http.Request) {
					w.Write(nil) // mock response with status 200
				},
				statusCode: 200,
			}
		},
	}

	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/foo", http.NoBody).WithContext(tc.ctx)
			w := httptest.NewRecorder()
			requireEABEnabled(tc.next)(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 {
				err := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &err))

				assert.Equals(t, tc.err.Type, err.Type)
				assert.Equals(t, tc.err.Message, err.Message)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, err.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}
		})
	}
}

func TestCreateExternalAccountKeyRequest_Validate(t *testing.T) {
	type fields struct {
		Reference string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "fail/reference-too-long",
			fields: fields{
				Reference: strings.Repeat("A", 257),
			},
			wantErr: true,
		},
		{
			name: "ok/empty-reference",
			fields: fields{
				Reference: "",
			},
			wantErr: false,
		},
		{
			name: "ok",
			fields: fields{
				Reference: "my-eab-reference",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &CreateExternalAccountKeyRequest{
				Reference: tt.fields.Reference,
			}
			if err := r.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("CreateExternalAccountKeyRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHandler_CreateExternalAccountKey(t *testing.T) {
	prov := &linkedca.Provisioner{
		Id:   "provID",
		Name: "provName",
	}
	type test struct {
		ctx        context.Context
		acmeDB     acme.DB
		body       []byte
		statusCode int
		eak        *linkedca.EABKey
		err        *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/ReadJSON": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			body := []byte("{!?}")
			return test{
				ctx:        ctx,
				body:       body,
				statusCode: 400,
				eak:        nil,
				err: &admin.Error{
					Type:    admin.ErrorBadRequestType.String(),
					Status:  400,
					Detail:  "bad request",
					Message: "error reading request body: error decoding json: invalid character '!' looking for beginning of object key string",
				},
			}
		},
		"fail/validate": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			req := CreateExternalAccountKeyRequest{
				Reference: strings.Repeat("A", 257),
			}
			body, err := json.Marshal(req)
			assert.FatalError(t, err)
			return test{
				ctx:        ctx,
				body:       body,
				statusCode: 400,
				eak:        nil,
				err: &admin.Error{
					Type:    admin.ErrorBadRequestType.String(),
					Status:  400,
					Detail:  "bad request",
					Message: "error validating request body: reference length 257 exceeds the maximum (256)",
				},
			}
		},
		"fail/acmeDB.GetExternalAccountKeyByReference": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			req := CreateExternalAccountKeyRequest{
				Reference: "an-external-key-reference",
			}
			body, err := json.Marshal(req)
			assert.FatalError(t, err)
			db := &acme.MockDB{
				MockGetExternalAccountKeyByReference: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "an-external-key-reference", reference)
					return nil, errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				acmeDB:     db,
				body:       body,
				statusCode: 500,
				eak:        nil,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "could not lookup external account key by reference: force",
				},
			}
		},
		"fail/reference-conflict-409": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			req := CreateExternalAccountKeyRequest{
				Reference: "an-external-key-reference",
			}
			body, err := json.Marshal(req)
			assert.FatalError(t, err)
			db := &acme.MockDB{
				MockGetExternalAccountKeyByReference: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "an-external-key-reference", reference)
					past := time.Now().Add(-24 * time.Hour)
					return &acme.ExternalAccountKey{
						ID:            "eakID",
						ProvisionerID: "provID",
						Reference:     "an-external-key-reference",
						HmacKey:       []byte{1, 3, 3, 7},
						CreatedAt:     past,
					}, nil
				},
			}
			return test{
				ctx:        ctx,
				acmeDB:     db,
				body:       body,
				statusCode: 409,
				eak:        nil,
				err: &admin.Error{
					Type:    admin.ErrorBadRequestType.String(),
					Status:  409,
					Detail:  "bad request",
					Message: "an ACME EAB key for provisioner 'provName' with reference 'an-external-key-reference' already exists",
				},
			}
		},
		"fail/acmeDB.CreateExternalAccountKey-no-reference": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			req := CreateExternalAccountKeyRequest{
				Reference: "",
			}
			body, err := json.Marshal(req)
			assert.FatalError(t, err)
			db := &acme.MockDB{
				MockCreateExternalAccountKey: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "", reference)
					return nil, errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				acmeDB:     db,
				body:       body,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "error creating ACME EAB key for provisioner 'provName': force",
				},
			}
		},
		"fail/acmeDB.CreateExternalAccountKey-with-reference": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			req := CreateExternalAccountKeyRequest{
				Reference: "an-external-key-reference",
			}
			body, err := json.Marshal(req)
			assert.FatalError(t, err)
			db := &acme.MockDB{
				MockGetExternalAccountKeyByReference: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "an-external-key-reference", reference)
					return nil, acme.ErrNotFound // simulating not found; skipping 409 conflict
				},
				MockCreateExternalAccountKey: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "an-external-key-reference", reference)
					return nil, errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				acmeDB:     db,
				body:       body,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "error creating ACME EAB key for provisioner 'provName' and reference 'an-external-key-reference': force",
				},
			}
		},
		"ok/no-reference": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			req := CreateExternalAccountKeyRequest{
				Reference: "",
			}
			body, err := json.Marshal(req)
			assert.FatalError(t, err)
			now := time.Now()
			db := &acme.MockDB{
				MockCreateExternalAccountKey: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "", reference)
					return &acme.ExternalAccountKey{
						ID:            "eakID",
						ProvisionerID: "provID",
						Reference:     "",
						HmacKey:       []byte{1, 3, 3, 7},
						CreatedAt:     now,
					}, nil
				},
			}
			return test{
				ctx:        ctx,
				acmeDB:     db,
				body:       body,
				statusCode: 201,
				eak: &linkedca.EABKey{
					Id:          "eakID",
					Provisioner: "provName",
					Reference:   "",
					HmacKey:     []byte{1, 3, 3, 7},
				},
			}
		},
		"ok/with-reference": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			req := CreateExternalAccountKeyRequest{
				Reference: "an-external-key-reference",
			}
			body, err := json.Marshal(req)
			assert.FatalError(t, err)
			now := time.Now()
			db := &acme.MockDB{
				MockGetExternalAccountKeyByReference: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "an-external-key-reference", reference)
					return nil, acme.ErrNotFound // simulating not found; skipping 409 conflict
				},
				MockCreateExternalAccountKey: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "an-external-key-reference", reference)
					return &acme.ExternalAccountKey{
						ID:            "eakID",
						ProvisionerID: "provID",
						Reference:     "an-external-key-reference",
						HmacKey:       []byte{1, 3, 3, 7},
						CreatedAt:     now,
					}, nil
				},
			}
			return test{
				ctx:        ctx,
				acmeDB:     db,
				body:       body,
				statusCode: 201,
				eak: &linkedca.EABKey{
					Id:          "eakID",
					Provisioner: "provName",
					Reference:   "an-external-key-reference",
					HmacKey:     []byte{1, 3, 3, 7},
				},
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			ctx := acme.NewDatabaseContext(tc.ctx, tc.acmeDB)
			aar := NewACMEAdminResponder()

			req := httptest.NewRequest("POST", "/foo", io.NopCloser(bytes.NewBuffer(tc.body))) // chi routing is prepared in test setup
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			aar.CreateExternalAccountKey(w, req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {

				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				adminErr := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &adminErr))

				assert.Equals(t, tc.err.Type, adminErr.Type)
				assert.Equals(t, tc.err.Message, adminErr.Message)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, adminErr.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}

			eabKey := &linkedca.EABKey{}
			err := readProtoJSON(res.Body, eabKey)
			assert.FatalError(t, err)
			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

			opts := []cmp.Option{cmpopts.IgnoreUnexported(linkedca.EABKey{})}
			if !cmp.Equal(tc.eak, eabKey, opts...) {
				t.Errorf("CreateExternalAccountKey diff =\n%s", cmp.Diff(tc.eak, eabKey, opts...))
			}

		})
	}
}

func TestHandler_DeleteExternalAccountKey(t *testing.T) {
	prov := &linkedca.Provisioner{
		Id:   "provID",
		Name: "provName",
	}
	type test struct {
		ctx        context.Context
		acmeDB     acme.DB
		statusCode int
		err        *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/acmeDB.DeleteExternalAccountKey": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			chiCtx.URLParams.Add("id", "keyID")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			db := &acme.MockDB{
				MockDeleteExternalAccountKey: func(ctx context.Context, provisionerID, keyID string) error {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "keyID", keyID)
					return errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				acmeDB:     db,
				statusCode: 500,
				err: &admin.Error{
					Type:    admin.ErrorServerInternalType.String(),
					Status:  500,
					Detail:  "the server experienced an internal error",
					Message: "error deleting ACME EAB Key 'keyID': force",
				},
			}
		},
		"ok": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			chiCtx.URLParams.Add("id", "keyID")
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			db := &acme.MockDB{
				MockDeleteExternalAccountKey: func(ctx context.Context, provisionerID, keyID string) error {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "keyID", keyID)
					return nil
				},
			}
			return test{
				ctx:        ctx,
				acmeDB:     db,
				statusCode: 200,
				err:        nil,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			ctx := acme.NewDatabaseContext(tc.ctx, tc.acmeDB)
			aar := NewACMEAdminResponder()

			req := httptest.NewRequest("DELETE", "/foo", http.NoBody) // chi routing is prepared in test setup
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			aar.DeleteExternalAccountKey(w, req)
			res := w.Result()
			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {
				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)
				adminErr := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &adminErr))
				assert.Equals(t, tc.err.Type, adminErr.Type)
				assert.Equals(t, tc.err.Message, adminErr.Message)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, adminErr.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			response := DeleteResponse{}
			assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &response))
			assert.Equals(t, "ok", response.Status)
			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

		})
	}
}

func TestHandler_GetExternalAccountKeys(t *testing.T) {
	prov := &linkedca.Provisioner{
		Id:   "provID",
		Name: "provName",
	}
	type test struct {
		ctx        context.Context
		acmeDB     acme.DB
		statusCode int
		req        *http.Request
		resp       GetExternalAccountKeysResponse
		err        *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/parse-cursor": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			req := httptest.NewRequest("GET", "/foo?limit=A", http.NoBody)
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			return test{
				ctx:        ctx,
				statusCode: 400,
				req:        req,
				acmeDB:     &acme.MockDB{},
				err: &admin.Error{
					Status:  400,
					Type:    admin.ErrorBadRequestType.String(),
					Detail:  "bad request",
					Message: "error parsing cursor and limit from query params: limit 'A' is not an integer: strconv.Atoi: parsing \"A\": invalid syntax",
				},
			}
		},
		"fail/acmeDB.GetExternalAccountKeyByReference": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			chiCtx.URLParams.Add("reference", "an-external-key-reference")
			req := httptest.NewRequest("GET", "/foo", http.NoBody)
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			db := &acme.MockDB{
				MockGetExternalAccountKeyByReference: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "an-external-key-reference", reference)
					return nil, errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				statusCode: 500,
				req:        req,
				acmeDB:     db,
				err: &admin.Error{
					Status:  500,
					Type:    admin.ErrorServerInternalType.String(),
					Detail:  "the server experienced an internal error",
					Message: "error retrieving external account key with reference 'an-external-key-reference': force",
				},
			}
		},
		"fail/acmeDB.GetExternalAccountKeys": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			req := httptest.NewRequest("GET", "/foo", http.NoBody)
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			db := &acme.MockDB{
				MockGetExternalAccountKeys: func(ctx context.Context, provisionerID, cursor string, limit int) ([]*acme.ExternalAccountKey, string, error) {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "", cursor)
					assert.Equals(t, 0, limit)
					return nil, "", errors.New("force")
				},
			}
			return test{
				ctx:        ctx,
				statusCode: 500,
				req:        req,
				acmeDB:     db,
				err: &admin.Error{
					Status:  500,
					Type:    admin.ErrorServerInternalType.String(),
					Detail:  "the server experienced an internal error",
					Message: "error retrieving external account keys: force",
				},
			}
		},
		"ok/reference-not-found": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			chiCtx.URLParams.Add("reference", "an-external-key-reference")
			req := httptest.NewRequest("GET", "/foo", http.NoBody)
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			db := &acme.MockDB{
				MockGetExternalAccountKeyByReference: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "an-external-key-reference", reference)
					return nil, nil // returning nil; no key found
				},
			}
			return test{
				ctx:        ctx,
				statusCode: 200,
				req:        req,
				resp: GetExternalAccountKeysResponse{
					EAKs: []*linkedca.EABKey{},
				},
				acmeDB: db,
				err:    nil,
			}
		},
		"ok/reference-found": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			chiCtx.URLParams.Add("reference", "an-external-key-reference")
			req := httptest.NewRequest("GET", "/foo", http.NoBody)
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			createdAt := time.Now().Add(-24 * time.Hour)
			var boundAt time.Time
			db := &acme.MockDB{
				MockGetExternalAccountKeyByReference: func(ctx context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "an-external-key-reference", reference)
					return &acme.ExternalAccountKey{
						ID:            "eakID",
						ProvisionerID: "provID",
						Reference:     "an-external-key-reference",
						CreatedAt:     createdAt,
					}, nil
				},
			}
			return test{
				ctx:        ctx,
				statusCode: 200,
				req:        req,
				resp: GetExternalAccountKeysResponse{
					EAKs: []*linkedca.EABKey{
						{
							Id:          "eakID",
							Provisioner: "provName",
							Reference:   "an-external-key-reference",
							CreatedAt:   timestamppb.New(createdAt),
							BoundAt:     timestamppb.New(boundAt),
						},
					},
				},
				acmeDB: db,
				err:    nil,
			}
		},
		"ok/multiple-keys": func(t *testing.T) test {
			chiCtx := chi.NewRouteContext()
			chiCtx.URLParams.Add("provisionerName", "provName")
			req := httptest.NewRequest("GET", "/foo", http.NoBody)
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx)
			ctx = linkedca.NewContextWithProvisioner(ctx, prov)
			createdAt := time.Now().Add(-24 * time.Hour)
			var boundAt time.Time
			boundAtSet := time.Now().Add(-12 * time.Hour)
			db := &acme.MockDB{
				MockGetExternalAccountKeys: func(ctx context.Context, provisionerID, cursor string, limit int) ([]*acme.ExternalAccountKey, string, error) {
					assert.Equals(t, "provID", provisionerID)
					assert.Equals(t, "", cursor)
					assert.Equals(t, 0, limit)
					return []*acme.ExternalAccountKey{
						{
							ID:            "eakID1",
							ProvisionerID: "provID",
							Reference:     "some-external-key-reference",
							HmacKey:       []byte{1, 3, 3, 7},
							CreatedAt:     createdAt,
						},
						{
							ID:            "eakID2",
							ProvisionerID: "provID",
							Reference:     "some-other-external-key-reference",
							HmacKey:       []byte{1, 3, 3, 7},
							CreatedAt:     createdAt.Add(1 * time.Hour),
						},
						{
							ID:            "eakID3",
							ProvisionerID: "provID",
							Reference:     "another-external-key-reference",
							HmacKey:       []byte{1, 3, 3, 7},
							CreatedAt:     createdAt,
							BoundAt:       boundAtSet,
							AccountID:     "accountID",
						},
					}, "", nil
				},
			}
			return test{
				ctx:        ctx,
				statusCode: 200,
				req:        req,
				resp: GetExternalAccountKeysResponse{
					EAKs: []*linkedca.EABKey{
						{
							Id:          "eakID1",
							Provisioner: "provName",
							Reference:   "some-external-key-reference",
							CreatedAt:   timestamppb.New(createdAt),
							BoundAt:     timestamppb.New(boundAt),
						},
						{
							Id:          "eakID2",
							Provisioner: "provName",
							Reference:   "some-other-external-key-reference",
							CreatedAt:   timestamppb.New(createdAt.Add(1 * time.Hour)),
							BoundAt:     timestamppb.New(boundAt),
						},
						{
							Id:          "eakID3",
							Provisioner: "provName",
							Reference:   "another-external-key-reference",
							CreatedAt:   timestamppb.New(createdAt),
							BoundAt:     timestamppb.New(boundAtSet),
							Account:     "accountID",
						},
					},
				},
				acmeDB: db,
				err:    nil,
			}
		},
	}
	for name, prep := range tests {
		tc := prep(t)
		t.Run(name, func(t *testing.T) {
			ctx := acme.NewDatabaseContext(tc.ctx, tc.acmeDB)
			aar := NewACMEAdminResponder()

			req := tc.req.WithContext(ctx)
			w := httptest.NewRecorder()

			aar.GetExternalAccountKeys(w, req)
			res := w.Result()
			assert.Equals(t, tc.statusCode, res.StatusCode)

			if res.StatusCode >= 400 {
				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.FatalError(t, err)

				adminErr := admin.Error{}
				assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &adminErr))

				assert.Equals(t, tc.err.Type, adminErr.Type)
				assert.Equals(t, tc.err.Message, adminErr.Message)
				assert.Equals(t, tc.err.StatusCode(), res.StatusCode)
				assert.Equals(t, tc.err.Detail, adminErr.Detail)
				assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])
				return
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			response := GetExternalAccountKeysResponse{}
			assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &response))

			assert.Equals(t, []string{"application/json"}, res.Header["Content-Type"])

			opts := []cmp.Option{cmpopts.IgnoreUnexported(linkedca.EABKey{}, timestamppb.Timestamp{})}
			if !cmp.Equal(tc.resp, response, opts...) {
				t.Errorf("h.GetExternalAccountKeys diff =\n%s", cmp.Diff(tc.resp, response, opts...))
			}
		})
	}
}

func Test_eakToLinked(t *testing.T) {
	tests := []struct {
		name string
		k    *acme.ExternalAccountKey
		want *linkedca.EABKey
	}{
		{
			name: "no-key",
			k:    nil,
			want: nil,
		},
		{
			name: "no-policy",
			k: &acme.ExternalAccountKey{
				ID:            "keyID",
				ProvisionerID: "provID",
				Reference:     "ref",
				AccountID:     "accID",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC).Add(-1 * time.Hour),
				BoundAt:       time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC),
				Policy:        nil,
			},
			want: &linkedca.EABKey{
				Id:          "keyID",
				Provisioner: "provID",
				HmacKey:     []byte{1, 3, 3, 7},
				Reference:   "ref",
				Account:     "accID",
				CreatedAt:   timestamppb.New(time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC).Add(-1 * time.Hour)),
				BoundAt:     timestamppb.New(time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC)),
				Policy:      nil,
			},
		},
		{
			name: "with-policy",
			k: &acme.ExternalAccountKey{
				ID:            "keyID",
				ProvisionerID: "provID",
				Reference:     "ref",
				AccountID:     "accID",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC).Add(-1 * time.Hour),
				BoundAt:       time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC),
				Policy: &acme.Policy{
					X509: acme.X509Policy{
						Allowed: acme.PolicyNames{
							DNSNames: []string{"*.local"},
							IPRanges: []string{"10.0.0.0/24"},
						},
						Denied: acme.PolicyNames{
							DNSNames: []string{"badhost.local"},
							IPRanges: []string{"10.0.0.30"},
						},
					},
				},
			},
			want: &linkedca.EABKey{
				Id:          "keyID",
				Provisioner: "provID",
				HmacKey:     []byte{1, 3, 3, 7},
				Reference:   "ref",
				Account:     "accID",
				CreatedAt:   timestamppb.New(time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC).Add(-1 * time.Hour)),
				BoundAt:     timestamppb.New(time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC)),
				Policy: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"*.local"},
							Ips: []string{"10.0.0.0/24"},
						},
						Deny: &linkedca.X509Names{
							Dns: []string{"badhost.local"},
							Ips: []string{"10.0.0.30"},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eakToLinked(tt.k); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("eakToLinked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_linkedEAKToCertificates(t *testing.T) {
	tests := []struct {
		name string
		k    *linkedca.EABKey
		want *acme.ExternalAccountKey
	}{
		{
			name: "no-key",
			k:    nil,
			want: nil,
		},
		{
			name: "no-policy",
			k: &linkedca.EABKey{
				Id:          "keyID",
				Provisioner: "provID",
				HmacKey:     []byte{1, 3, 3, 7},
				Reference:   "ref",
				Account:     "accID",
				CreatedAt:   timestamppb.New(time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC).Add(-1 * time.Hour)),
				BoundAt:     timestamppb.New(time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC)),
				Policy:      nil,
			},
			want: &acme.ExternalAccountKey{
				ID:            "keyID",
				ProvisionerID: "provID",
				Reference:     "ref",
				AccountID:     "accID",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC).Add(-1 * time.Hour),
				BoundAt:       time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC),
				Policy:        nil,
			},
		},
		{
			name: "no-x509-policy",
			k: &linkedca.EABKey{
				Id:          "keyID",
				Provisioner: "provID",
				HmacKey:     []byte{1, 3, 3, 7},
				Reference:   "ref",
				Account:     "accID",
				CreatedAt:   timestamppb.New(time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC).Add(-1 * time.Hour)),
				BoundAt:     timestamppb.New(time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC)),
				Policy:      &linkedca.Policy{},
			},
			want: &acme.ExternalAccountKey{
				ID:            "keyID",
				ProvisionerID: "provID",
				Reference:     "ref",
				AccountID:     "accID",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC).Add(-1 * time.Hour),
				BoundAt:       time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC),
				Policy:        &acme.Policy{},
			},
		},
		{
			name: "with-x509-policy",
			k: &linkedca.EABKey{
				Id:          "keyID",
				Provisioner: "provID",
				HmacKey:     []byte{1, 3, 3, 7},
				Reference:   "ref",
				Account:     "accID",
				CreatedAt:   timestamppb.New(time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC).Add(-1 * time.Hour)),
				BoundAt:     timestamppb.New(time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC)),
				Policy: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"*.local"},
							Ips: []string{"10.0.0.0/24"},
						},
						Deny: &linkedca.X509Names{
							Dns: []string{"badhost.local"},
							Ips: []string{"10.0.0.30"},
						},
						AllowWildcardNames: true,
					},
				},
			},
			want: &acme.ExternalAccountKey{
				ID:            "keyID",
				ProvisionerID: "provID",
				Reference:     "ref",
				AccountID:     "accID",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC).Add(-1 * time.Hour),
				BoundAt:       time.Date(2022, 04, 12, 9, 30, 30, 0, time.UTC),
				Policy: &acme.Policy{
					X509: acme.X509Policy{
						Allowed: acme.PolicyNames{
							DNSNames: []string{"*.local"},
							IPRanges: []string{"10.0.0.0/24"},
						},
						Denied: acme.PolicyNames{
							DNSNames: []string{"badhost.local"},
							IPRanges: []string{"10.0.0.30"},
						},
						AllowWildcardNames: true,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := linkedEAKToCertificates(tt.k); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("linkedEAKToCertificates() = %v, want %v", got, tt.want)
			}
		})
	}
}
