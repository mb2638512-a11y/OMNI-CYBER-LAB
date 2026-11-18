package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type server struct {
	db             *pgxpool.Pool
	googleClient   *http.Client
	apiKey         []byte
	allowedPackages map[string]bool
	allowedProducts map[string]bool
}

type verifyRequest struct {
	PackageName   string `json:"packageName"`
	ProductID     string `json:"productId"`
	PurchaseToken string `json:"purchaseToken"`
	UserID        string `json:"userId"`
	PurchaseType  string `json:"purchaseType"`
}

type productPurchase struct {
	ProductID           string `json:"productId"`
	PurchaseState       int    `json:"purchaseState"`
	AcknowledgementState int   `json:"acknowledgementState"`
	ConsumptionState    int    `json:"consumptionState"`
	OrderID             string `json:"orderId"`
	PurchaseTimeMillis  string `json:"purchaseTimeMillis"`
}

type subscriptionPurchase struct {
	SubscriptionState string `json:"subscriptionState"`
	LineItems []struct {
		ProductID string `json:"productId"`
		ExpiryTime string `json:"expiryTime"`
	} `json:"lineItems"`
}

type verifyResponse struct {
	Verified bool `json:"verified"`
	Entitled bool `json:"entitled"`
	Duplicate bool `json:"duplicate"`
	State string `json:"state"`
	ProductID string `json:"productId"`
	Message string `json:"message"`
}

func envSet(name string) map[string]bool {
	out := map[string]bool{}
	for _, value := range strings.Split(os.Getenv(name), ",") {
		value = strings.TrimSpace(value)
		if value != "" { out[value] = true }
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *server) authorized(r *http.Request) bool {
	header := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if len(s.apiKey) == 0 || len(header) != len(s.apiKey) { return false }
	return subtle.ConstantTimeCompare([]byte(header), s.apiKey) == 1
}

func (s *server) verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error":"POST required"}); return }
	if !s.authorized(r) { writeJSON(w, http.StatusUnauthorized, map[string]string{"error":"unauthorized"}); return }
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var req verifyRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil { writeJSON(w, http.StatusBadRequest, map[string]string{"error":"invalid request body"}); return }
	if req.PackageName == "" || req.ProductID == "" || req.PurchaseToken == "" || req.UserID == "" || (req.PurchaseType != "product" && req.PurchaseType != "subscription") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error":"packageName, productId, purchaseToken, userId and purchaseType are required"}); return
	}
	if !s.allowedPackages[req.PackageName] || !s.allowedProducts[req.ProductID] {
		writeJSON(w, http.StatusForbidden, map[string]string{"error":"package or product is not allowlisted"}); return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second); defer cancel()
	result, err := s.verifyWithGoogle(ctx, req)
	if err != nil {
		log.Printf("Play verification failed package=%s product=%s error=%v", req.PackageName, req.ProductID, err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error":"Google Play verification unavailable or rejected; no entitlement granted"}); return
	}
	if !result.Verified || !result.Entitled {
		writeJSON(w, http.StatusPaymentRequired, result); return
	}
	tokenHash := sha256.Sum256([]byte(req.PurchaseToken))
	hashHex := hex.EncodeToString(tokenHash[:])
	var existingUser string
	err = s.db.QueryRow(ctx, "SELECT user_id FROM play_purchase_ledger WHERE token_sha256=$1", hashHex).Scan(&existingUser)
	if err == nil && existingUser != req.UserID {
		writeJSON(w, http.StatusConflict, map[string]string{"error":"purchase token is already bound to a different account"}); return
	}
	if err != nil && err.Error() != "no rows in result set" {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error":"ledger lookup failed"}); return
	}
	_, err = s.db.Exec(ctx, `INSERT INTO play_purchase_ledger(token_sha256, package_name, product_id, purchase_type, user_id, purchase_state, entitled, verified_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,NOW())
		ON CONFLICT(token_sha256) DO UPDATE SET purchase_state=EXCLUDED.purchase_state, entitled=EXCLUDED.entitled, verified_at=NOW()
		WHERE play_purchase_ledger.user_id=EXCLUDED.user_id`,
		hashHex, req.PackageName, req.ProductID, req.PurchaseType, req.UserID, result.State, result.Entitled)
	if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]string{"error":"could not persist verified purchase"}); return }
	result.Duplicate = existingUser == req.UserID
	result.Message = "Google Play token verified. Apply entitlement idempotently from this server-side record."
	writeJSON(w, http.StatusOK, result)
}

func (s *server) verifyWithGoogle(ctx context.Context, req verifyRequest) (verifyResponse, error) {
	base := "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/" + url.PathEscape(req.PackageName) + "/purchases/"
	var endpoint string
	if req.PurchaseType == "product" {
		endpoint = base + "products/" + url.PathEscape(req.ProductID) + "/tokens/" + url.PathEscape(req.PurchaseToken)
	} else {
		endpoint = base + "subscriptionsv2/tokens/" + url.PathEscape(req.PurchaseToken)
	}
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	resp, err := s.googleClient.Do(httpReq)
	if err != nil { return verifyResponse{}, err }
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil { return verifyResponse{}, err }
	if resp.StatusCode != http.StatusOK { return verifyResponse{}, fmt.Errorf("publisher API status %d", resp.StatusCode) }
	if req.PurchaseType == "product" {
		var p productPurchase
		if err := json.Unmarshal(body, &p); err != nil { return verifyResponse{}, err }
		if p.ProductID != req.ProductID { return verifyResponse{}, errors.New("product ID mismatch") }
		state := map[int]string{0:"PURCHASED",1:"CANCELED",2:"PENDING"}[p.PurchaseState]
		return verifyResponse{Verified:true, Entitled:p.PurchaseState==0, State:state, ProductID:p.ProductID}, nil
	}
	var p subscriptionPurchase
	if err := json.Unmarshal(body, &p); err != nil { return verifyResponse{}, err }
	matched := false
	entitled := false
	for _, item := range p.LineItems {
		if item.ProductID != req.ProductID { continue }
		matched = true
		expiry, parseErr := time.Parse(time.RFC3339, item.ExpiryTime)
		if parseErr == nil && expiry.After(time.Now()) && (p.SubscriptionState=="SUBSCRIPTION_STATE_ACTIVE" || p.SubscriptionState=="SUBSCRIPTION_STATE_IN_GRACE_PERIOD" || p.SubscriptionState=="SUBSCRIPTION_STATE_CANCELED") { entitled = true }
	}
	if !matched { return verifyResponse{}, errors.New("subscription product mismatch") }
	return verifyResponse{Verified:true, Entitled:entitled, State:p.SubscriptionState, ProductID:req.ProductID}, nil
}

func main() {
	apiKey := os.Getenv("OMNI_VERIFIER_API_KEY")
	databaseURL := os.Getenv("DATABASE_URL")
	credentials := os.Getenv("GOOGLE_PLAY_SERVICE_ACCOUNT_JSON")
	if apiKey == "" || databaseURL == "" || credentials == "" {
		log.Fatal("OMNI_VERIFIER_API_KEY, DATABASE_URL and GOOGLE_PLAY_SERVICE_ACCOUNT_JSON are required")
	}
	jwtConfig, err := google.JWTConfigFromJSON([]byte(credentials), "https://www.googleapis.com/auth/androidpublisher")
	if err != nil { log.Fatalf("invalid Google service-account JSON: %v", err) }
	db, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil { log.Fatalf("database connection: %v", err) }
	defer db.Close()
	s := &server{db:db, googleClient:oauth2.NewClient(context.Background(), jwtConfig.TokenSource(context.Background())), apiKey:[]byte(apiKey), allowedPackages:envSet("ALLOWED_PACKAGE_NAMES"), allowedProducts:envSet("ALLOWED_PRODUCT_IDS")}
	if len(s.allowedPackages)==0 || len(s.allowedProducts)==0 { log.Fatal("ALLOWED_PACKAGE_NAMES and ALLOWED_PRODUCT_IDS must be configured") }
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { if r.Method != http.MethodGet { writeJSON(w,405,map[string]string{"error":"GET required"}); return }; writeJSON(w,200,map[string]string{"status":"ok"}) })
	mux.HandleFunc("/v1/play/verify", s.verify)
	port := os.Getenv("PORT"); if port=="" { port="8080" }
	srv := &http.Server{Addr:":"+port, Handler:mux, ReadHeaderTimeout:5*time.Second, ReadTimeout:10*time.Second, WriteTimeout:20*time.Second, IdleTimeout:60*time.Second}
	log.Printf("Play verifier listening on :%s", port)
	log.Fatal(srv.ListenAndServe())
}
