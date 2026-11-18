package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)
func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fakeClient(body string, status int) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode:status, Body:io.NopCloser(strings.NewReader(body)), Header:make(http.Header), Request:r}, nil
	})}
}

func TestProductPurchaseStates(t *testing.T) {
	cases := []struct{name, body string; entitled bool; state string}{
		{"purchased", `{"productId":"vip.monthly","purchaseState":0}`, true, "PURCHASED"},
		{"pending", `{"productId":"vip.monthly","purchaseState":2}`, false, "PENDING"},
		{"canceled", `{"productId":"vip.monthly","purchaseState":1}`, false, "CANCELED"},
	}
	for _, tc := range cases { t.Run(tc.name, func(t *testing.T) {
		s := &server{googleClient:fakeClient(tc.body,http.StatusOK)}
		got, err := s.verifyWithGoogle(context.Background(), verifyRequest{PackageName:"com.example.owner",ProductID:"vip.monthly",PurchaseToken:"test-token",PurchaseType:"product"})
		if err != nil { t.Fatal(err) }
		if got.Entitled != tc.entitled || got.State != tc.state || !got.Verified { t.Fatalf("unexpected result: %+v",got) }
	}) }
}

func TestProductMismatchRejected(t *testing.T) {
	s := &server{googleClient:fakeClient(`{"productId":"other.product","purchaseState":0}`,http.StatusOK)}
	_, err := s.verifyWithGoogle(context.Background(), verifyRequest{PackageName:"com.example.owner",ProductID:"vip.monthly",PurchaseToken:"test-token",PurchaseType:"product"})
	if err == nil { t.Fatal("expected product mismatch rejection") }
}

func TestSubscriptionExpiredNotEntitled(t *testing.T) {
	body := `{"subscriptionState":"SUBSCRIPTION_STATE_ACTIVE","lineItems":[{"productId":"vip.monthly","expiryTime":"2020-01-01T00:00:00Z"}]}`
	s := &server{googleClient:fakeClient(body,http.StatusOK)}
	got, err := s.verifyWithGoogle(context.Background(), verifyRequest{PackageName:"com.example.owner",ProductID:"vip.monthly",PurchaseToken:"test-token",PurchaseType:"subscription"})
	if err != nil { t.Fatal(err) }
	if !got.Verified || got.Entitled { t.Fatalf("expired subscription must not be entitled: %+v",got) }
}

func TestWalletInputValidation(t *testing.T) {
	if !validWalletIdentity("account-123", "GOLD", "transaction-0001") { t.Fatal("valid wallet identity rejected") }
	invalid := []struct{user,currency,tx string}{
		{"","GOLD","transaction-0001"},
		{"user 1","GOLD","transaction-0001"},
		{"user-1","gold","transaction-0001"},
		{"user-1","GOLD","short"},
		{"user-1","GOLD","transaction 0001"},
		{"user-1","TOO_LONG_CURRENCY_123","transaction-0001"},
	}
	for _, v := range invalid {
		if validWalletIdentity(v.user,v.currency,v.tx) { t.Fatalf("invalid wallet identity accepted: %+v",v) }
	}
}


func TestSubscriptionEntitlementStates(t *testing.T) {
	future := "2099-01-01T00:00:00Z"
	cases := []struct {
		name, state, expiry string
		entitled bool
	}{
		{"active future", "SUBSCRIPTION_STATE_ACTIVE", future, true},
		{"grace future", "SUBSCRIPTION_STATE_IN_GRACE_PERIOD", future, true},
		{"canceled until expiry", "SUBSCRIPTION_STATE_CANCELED", future, true},
		{"paused", "SUBSCRIPTION_STATE_PAUSED", future, false},
		{"on hold", "SUBSCRIPTION_STATE_ON_HOLD", future, false},
		{"expired", "SUBSCRIPTION_STATE_ACTIVE", "2020-01-01T00:00:00Z", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"subscriptionState":"` + tc.state + `","lineItems":[{"productId":"vip.monthly","expiryTime":"` + tc.expiry + `"}]}`
			s := &server{googleClient: fakeClient(body, http.StatusOK)}
			got, err := s.verifyWithGoogle(context.Background(), verifyRequest{
				PackageName: "com.example.owner", ProductID: "vip.monthly",
				PurchaseToken: "test-token", PurchaseType: "subscription",
			})
			if err != nil { t.Fatal(err) }
			if !got.Verified || got.Entitled != tc.entitled {
				t.Fatalf("unexpected entitlement result: %+v", got)
			}
		})
	}
}

func TestSubscriptionWrongProductRejected(t *testing.T) {
	body := `{"subscriptionState":"SUBSCRIPTION_STATE_ACTIVE","lineItems":[{"productId":"other.sku","expiryTime":"2099-01-01T00:00:00Z"}]}`
	s := &server{googleClient: fakeClient(body, http.StatusOK)}
	_, err := s.verifyWithGoogle(context.Background(), verifyRequest{
		PackageName: "com.example.owner", ProductID: "vip.monthly",
		PurchaseToken: "test-token", PurchaseType: "subscription",
	})
	if err == nil { t.Fatal("expected subscription product mismatch rejection") }
}


func TestAuthorizationRequiresExactBearerScheme(t *testing.T) {
	s := &server{apiKey: []byte("test-secret-key")}
	cases := []struct {
		name, header string
		want bool
	}{
		{"valid bearer", "Bearer test-secret-key", true},
		{"missing scheme", "test-secret-key", false},
		{"wrong key", "Bearer wrong-secret", false},
		{"empty bearer", "Bearer ", false},
		{"leading whitespace", " Bearer test-secret-key", false},
		{"trailing whitespace", "Bearer test-secret-key ", false},
		{"embedded whitespace", "Bearer test secret key", false},
		{"wrong scheme case", "bearer test-secret-key", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodPost, "/v1/play/verify", nil)
			r.Header.Set("Authorization", tc.header)
			if got := s.authorized(r); got != tc.want {
				t.Fatalf("authorized()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestAuthorizationFailsClosedWithoutConfiguredKey(t *testing.T) {
	s := &server{}
	r, _ := http.NewRequest(http.MethodPost, "/v1/play/verify", nil)
	r.Header.Set("Authorization", "Bearer any-value")
	if s.authorized(r) {
		t.Fatal("authorization must fail when server key is not configured")
	}
}


func TestDecodeJSONBodyRejectsTrailingValues(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"valid"} {"admin":true}`))
	w := httptest.NewRecorder()
	var dst struct { Name string `json:"name"` }
	if err := decodeJSONBody(w, r, 1024, &dst, true); err == nil { t.Fatal("expected trailing JSON value to be rejected") }
}
func TestDecodeJSONBodyRejectsUnknownFields(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"valid","isAdmin":true}`))
	w := httptest.NewRecorder()
	var dst struct { Name string `json:"name"` }
	if err := decodeJSONBody(w, r, 1024, &dst, true); err == nil { t.Fatal("expected unknown JSON field to be rejected") }
}
func TestDecodeJSONBodyEnforcesSizeLimit(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"this body is too long"}`))
	w := httptest.NewRecorder()
	var dst struct { Name string `json:"name"` }
	if err := decodeJSONBody(w, r, 8, &dst, true); err == nil { t.Fatal("expected oversized JSON body to be rejected") }
}
func TestDecodeJSONBodyAllowsProviderExtensionFields(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"message":{"data":"e30="},"providerFutureField":true}`))
	w := httptest.NewRecorder()
	var dst rtdnEnvelope
	if err := decodeJSONBody(w, r, 1024, &dst, false); err != nil { t.Fatalf("provider extension field should be tolerated: %v", err) }
}
