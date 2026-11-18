package main

import (
	"context"
	"io"
	"net/http"
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
