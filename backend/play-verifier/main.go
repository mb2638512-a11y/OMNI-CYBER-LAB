package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/base64"
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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
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

type walletFulfillRequest struct {
	PackageName string `json:"packageName"`
	ProductID string `json:"productId"`
	PurchaseToken string `json:"purchaseToken"`
	UserID string `json:"userId"`
}

type walletSpendRequest struct {
	UserID string `json:"userId"`
	Currency string `json:"currency"`
	Amount int64 `json:"amount"`
	TransactionID string `json:"transactionId"`
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
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) { return false }
	token := strings.TrimPrefix(header, prefix)
	if token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, " \\t\\r\\n") { return false }
	if len(s.apiKey) == 0 || len(token) != len(s.apiKey) { return false }
	return subtle.ConstantTimeCompare([]byte(token), s.apiKey) == 1
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
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error":"ledger lookup failed"}); return
	}
	var storedHash string
	err = s.db.QueryRow(ctx, `INSERT INTO play_purchase_ledger(token_sha256, package_name, product_id, purchase_type, user_id, purchase_state, entitled, verified_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,NOW())
		ON CONFLICT(token_sha256) DO UPDATE SET purchase_state=EXCLUDED.purchase_state, entitled=EXCLUDED.entitled, verified_at=NOW()
		WHERE play_purchase_ledger.user_id=EXCLUDED.user_id
		RETURNING token_sha256`,
		hashHex, req.PackageName, req.ProductID, req.PurchaseType, req.UserID, result.State, result.Entitled).Scan(&storedHash)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusConflict, map[string]string{"error":"purchase token is already bound to a different account"}); return
	}
	if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]string{"error":"could not persist verified purchase"}); return }
	result.Duplicate = existingUser == req.UserID
	result.Message = "Google Play token verified. Apply entitlement idempotently from this server-side record."
	writeJSON(w, http.StatusOK, result)
}

func validWalletIdentity(userID, currency, transactionID string) bool {
	if len(userID) < 1 || len(userID) > 128 || strings.ContainsAny(userID, " \t\r\n") { return false }
	if len(currency) < 2 || len(currency) > 16 { return false }
	for _, c := range currency { if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') { return false } }
	if len(transactionID) < 8 || len(transactionID) > 100 || strings.ContainsAny(transactionID, " \t\r\n") { return false }
	return true
}

func (s *server) fulfillWallet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error":"POST required"}); return }
	if !s.authorized(r) { writeJSON(w, http.StatusUnauthorized, map[string]string{"error":"unauthorized"}); return }
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var req walletFulfillRequest
	dec := json.NewDecoder(r.Body); dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil { writeJSON(w, http.StatusBadRequest, map[string]string{"error":"invalid request body"}); return }
	if req.PackageName=="" || req.ProductID=="" || req.PurchaseToken=="" || req.UserID=="" || !s.allowedPackages[req.PackageName] || !s.allowedProducts[req.ProductID] {
		writeJSON(w, http.StatusForbidden, map[string]string{"error":"missing or non-allowlisted purchase identity"}); return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second); defer cancel()
	hash := sha256.Sum256([]byte(req.PurchaseToken)); tokenHash := hex.EncodeToString(hash[:])
	tx, err := s.db.Begin(ctx); if err != nil { writeJSON(w,500,map[string]string{"error":"wallet transaction could not start"}); return }
	defer tx.Rollback(ctx)
	var owner, pkg, product, purchaseType, state string
	var entitled bool
	err = tx.QueryRow(ctx, `SELECT user_id, package_name, product_id, purchase_type, purchase_state, entitled FROM play_purchase_ledger WHERE token_sha256=$1 FOR UPDATE`, tokenHash).Scan(&owner,&pkg,&product,&purchaseType,&state,&entitled)
	if err != nil { writeJSON(w,http.StatusForbidden,map[string]string{"error":"purchase token has not been verified and recorded"}); return }
	if owner!=req.UserID || pkg!=req.PackageName || product!=req.ProductID || purchaseType!="product" || !entitled {
		writeJSON(w,http.StatusForbidden,map[string]string{"error":"verified purchase does not match this user, product or consumable product type"}); return
	}
	var currency string; var amount int64
	err = tx.QueryRow(ctx, `SELECT currency, amount FROM wallet_product_grants WHERE package_name=$1 AND product_id=$2`, req.PackageName, req.ProductID).Scan(&currency,&amount)
	if err != nil || amount<=0 || amount>1000000000 || !validWalletIdentity(req.UserID,currency,"play:"+tokenHash) {
		writeJSON(w,http.StatusForbidden,map[string]string{"error":"no valid server-side currency grant is configured for this product"}); return
	}
	var inserted string
	err = tx.QueryRow(ctx, `INSERT INTO wallet_transactions(transaction_id,user_id,currency,amount,direction,source,purchase_token_sha256,created_at)
		VALUES($1,$2,$3,$4,'CREDIT','PLAY_PURCHASE',$5,NOW())
		ON CONFLICT DO NOTHING RETURNING transaction_id`, "play:"+tokenHash,req.UserID,currency,amount,tokenHash).Scan(&inserted)
	if errors.Is(err,pgx.ErrNoRows) {
		var balance int64
		_ = tx.QueryRow(ctx,`SELECT balance FROM wallet_balances WHERE user_id=$1 AND currency=$2`,req.UserID,currency).Scan(&balance)
		if err:=tx.Commit(ctx); err!=nil { writeJSON(w,500,map[string]string{"error":"wallet transaction commit failed"}); return }
		writeJSON(w,200,map[string]any{"credited":false,"duplicate":true,"currency":currency,"balance":balance,"message":"Purchase was already fulfilled; no duplicate credit issued."}); return
	}
	if err != nil { writeJSON(w,500,map[string]string{"error":"purchase fulfillment ledger write failed"}); return }
	_, err = tx.Exec(ctx,`INSERT INTO wallet_balances(user_id,currency,balance) VALUES($1,$2,0) ON CONFLICT(user_id,currency) DO NOTHING`,req.UserID,currency)
	if err != nil { writeJSON(w,500,map[string]string{"error":"wallet initialization failed"}); return }
	var balance int64
	err = tx.QueryRow(ctx,`UPDATE wallet_balances SET balance=balance+$1 WHERE user_id=$2 AND currency=$3 AND balance <= 9000000000000000-$1 RETURNING balance`,amount,req.UserID,currency).Scan(&balance)
	if err != nil { writeJSON(w,500,map[string]string{"error":"wallet credit would exceed the supported balance limit"}); return }
	if err:=tx.Commit(ctx); err!=nil { writeJSON(w,500,map[string]string{"error":"wallet fulfillment commit failed"}); return }
	writeJSON(w,200,map[string]any{"credited":true,"duplicate":false,"currency":currency,"creditedAmount":amount,"balance":balance,"message":"Verified purchase credited exactly once to the server-side wallet."})
}

func (s *server) spendWallet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { writeJSON(w,http.StatusMethodNotAllowed,map[string]string{"error":"POST required"}); return }
	if !s.authorized(r) { writeJSON(w,http.StatusUnauthorized,map[string]string{"error":"unauthorized"}); return }
	r.Body=http.MaxBytesReader(w,r.Body,8*1024)
	var req walletSpendRequest
	dec:=json.NewDecoder(r.Body); dec.DisallowUnknownFields()
	if err:=dec.Decode(&req); err!=nil { writeJSON(w,http.StatusBadRequest,map[string]string{"error":"invalid request body"}); return }
	if !validWalletIdentity(req.UserID,req.Currency,req.TransactionID) || req.Amount<=0 || req.Amount>1000000000 {
		writeJSON(w,http.StatusBadRequest,map[string]string{"error":"invalid user, currency, transaction ID or amount"}); return
	}
	ctx,cancel:=context.WithTimeout(r.Context(),8*time.Second); defer cancel()
	tx,err:=s.db.Begin(ctx); if err!=nil { writeJSON(w,500,map[string]string{"error":"wallet transaction could not start"}); return }
	defer tx.Rollback(ctx)
	var oldUser,oldCurrency,oldDirection string; var oldAmount int64
	err=tx.QueryRow(ctx,`SELECT user_id,currency,direction,amount FROM wallet_transactions WHERE transaction_id=$1`,req.TransactionID).Scan(&oldUser,&oldCurrency,&oldDirection,&oldAmount)
	if err==nil {
		if oldUser!=req.UserID || oldCurrency!=req.Currency || oldDirection!="DEBIT" || oldAmount!=req.Amount { writeJSON(w,http.StatusConflict,map[string]string{"error":"transaction ID was already used for a different operation"}); return }
		var balance int64; _=tx.QueryRow(ctx,`SELECT balance FROM wallet_balances WHERE user_id=$1 AND currency=$2`,req.UserID,req.Currency).Scan(&balance)
		if err:=tx.Commit(ctx); err!=nil { writeJSON(w,500,map[string]string{"error":"wallet read commit failed"}); return }
		writeJSON(w,200,map[string]any{"spent":false,"duplicate":true,"currency":req.Currency,"balance":balance}); return
	}
	if !errors.Is(err,pgx.ErrNoRows) { writeJSON(w,500,map[string]string{"error":"wallet idempotency lookup failed"}); return }
	var balance int64
	err=tx.QueryRow(ctx,`UPDATE wallet_balances SET balance=balance-$1 WHERE user_id=$2 AND currency=$3 AND balance >= $1 RETURNING balance`,req.Amount,req.UserID,req.Currency).Scan(&balance)
	if errors.Is(err,pgx.ErrNoRows) { writeJSON(w,http.StatusPaymentRequired,map[string]string{"error":"insufficient server-side balance; no spend recorded"}); return }
	if err!=nil { writeJSON(w,500,map[string]string{"error":"wallet debit failed"}); return }
	_,err=tx.Exec(ctx,`INSERT INTO wallet_transactions(transaction_id,user_id,currency,amount,direction,source,created_at) VALUES($1,$2,$3,$4,'DEBIT','APP_SPEND',NOW())`,req.TransactionID,req.UserID,req.Currency,req.Amount)
	if err!=nil { writeJSON(w,500,map[string]string{"error":"wallet debit ledger write failed"}); return }
	if err:=tx.Commit(ctx); err!=nil { writeJSON(w,500,map[string]string{"error":"wallet debit commit failed"}); return }
	writeJSON(w,200,map[string]any{"spent":true,"duplicate":false,"currency":req.Currency,"spentAmount":req.Amount,"balance":balance})
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


type rtdnEnvelope struct {
 Message struct { Data string `json:"data"`; MessageID string `json:"messageId"` } `json:"message"`
 Subscription string `json:"subscription"`
}
type rtdnData struct {
 PackageName string `json:"packageName"`
 SubscriptionNotification *struct {
  Version string `json:"version"`
  NotificationType int `json:"notificationType"`
  PurchaseToken string `json:"purchaseToken"`
  SubscriptionID string `json:"subscriptionId"`
 } `json:"subscriptionNotification"`
 TestNotification *struct { Version string `json:"version"` } `json:"testNotification"`
}
func (s *server) rtdn(w http.ResponseWriter, r *http.Request) {
 if r.Method != http.MethodPost { writeJSON(w,405,map[string]string{"error":"POST required"}); return }
 audience:=strings.TrimSpace(os.Getenv("PUBSUB_PUSH_AUDIENCE")); expectedEmail:=strings.TrimSpace(os.Getenv("PUBSUB_PUSH_SERVICE_ACCOUNT_EMAIL"))
 auth:=strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"),"Bearer "))
 if audience=="" || expectedEmail=="" || auth=="" { writeJSON(w,401,map[string]string{"error":"Pub/Sub OIDC configuration required"}); return }
 ctx,cancel:=context.WithTimeout(r.Context(),12*time.Second); defer cancel()
 payload,err:=idtoken.Validate(ctx,auth,audience)
 if err!=nil || payload.Claims["email"]!=expectedEmail || payload.Claims["email_verified"]!=true { writeJSON(w,401,map[string]string{"error":"invalid Pub/Sub push identity"}); return }
 r.Body=http.MaxBytesReader(w,r.Body,128*1024)
 var envelope rtdnEnvelope; dec:=json.NewDecoder(r.Body)
 if err:=dec.Decode(&envelope); err!=nil || envelope.Message.Data=="" { writeJSON(w,400,map[string]string{"error":"invalid Pub/Sub envelope"}); return }
 raw,err:=base64.StdEncoding.DecodeString(envelope.Message.Data); if err!=nil { writeJSON(w,400,map[string]string{"error":"invalid Pub/Sub data encoding"}); return }
 var data rtdnData; if err:=json.Unmarshal(raw,&data); err!=nil { writeJSON(w,400,map[string]string{"error":"invalid RTDN payload"}); return }
 if data.TestNotification!=nil { writeJSON(w,200,map[string]string{"status":"test notification acknowledged"}); return }
 n:=data.SubscriptionNotification
 if n==nil || n.PurchaseToken=="" || data.PackageName=="" || !s.allowedPackages[data.PackageName] { writeJSON(w,200,map[string]string{"status":"ignored unsupported or non-allowlisted notification"}); return }
 hash:=sha256.Sum256([]byte(n.PurchaseToken)); tokenHash:=hex.EncodeToString(hash[:])
 var userID,productID string
 err=s.db.QueryRow(ctx,"SELECT user_id,product_id FROM play_purchase_ledger WHERE token_sha256=$1 AND package_name=$2 AND purchase_type='subscription'",tokenHash,data.PackageName).Scan(&userID,&productID)
 if errors.Is(err,pgx.ErrNoRows) { writeJSON(w,200,map[string]string{"status":"notification received; no previously verified subscription record"}); return }
 if err!=nil { writeJSON(w,500,map[string]string{"error":"subscription ledger lookup failed"}); return }
 if n.SubscriptionID!="" && n.SubscriptionID!=productID { writeJSON(w,200,map[string]string{"status":"notification product mismatch ignored"}); return }
 result,err:=s.verifyWithGoogle(ctx,verifyRequest{PackageName:data.PackageName,ProductID:productID,PurchaseToken:n.PurchaseToken,UserID:userID,PurchaseType:"subscription"})
 if err!=nil { writeJSON(w,503,map[string]string{"error":"Google Play reconciliation failed; retry notification"}); return }
 _,err=s.db.Exec(ctx,"UPDATE play_purchase_ledger SET purchase_state=$1,entitled=$2,verified_at=NOW() WHERE token_sha256=$3 AND user_id=$4",result.State,result.Entitled,tokenHash,userID)
 if err!=nil { writeJSON(w,500,map[string]string{"error":"subscription reconciliation persistence failed"}); return }
 writeJSON(w,200,map[string]any{"status":"subscription reconciled","entitled":result.Entitled,"state":result.State})
}
type purchaseActionRequest struct { PackageName string `json:"packageName"`; ProductID string `json:"productId"`; PurchaseToken string `json:"purchaseToken"`; UserID string `json:"userId"` }
func (s *server) purchaseAction(consume bool) http.HandlerFunc {
 return func(w http.ResponseWriter,r *http.Request) {
  if r.Method!=http.MethodPost { writeJSON(w,405,map[string]string{"error":"POST required"}); return }
  if !s.authorized(r) { writeJSON(w,401,map[string]string{"error":"unauthorized"}); return }
  r.Body=http.MaxBytesReader(w,r.Body,16*1024)
  var req purchaseActionRequest; dec:=json.NewDecoder(r.Body); dec.DisallowUnknownFields()
  if err:=dec.Decode(&req); err!=nil { writeJSON(w,400,map[string]string{"error":"invalid request body"}); return }
  if req.PackageName=="" || req.ProductID=="" || req.PurchaseToken=="" || req.UserID=="" || !s.allowedPackages[req.PackageName] || !s.allowedProducts[req.ProductID] { writeJSON(w,403,map[string]string{"error":"missing or non-allowlisted purchase identity"}); return }
  ctx,cancel:=context.WithTimeout(r.Context(),12*time.Second); defer cancel()
  hash:=sha256.Sum256([]byte(req.PurchaseToken)); tokenHash:=hex.EncodeToString(hash[:])
  var owner,pkg,product,kind string; var entitled bool
  err:=s.db.QueryRow(ctx,"SELECT user_id,package_name,product_id,purchase_type,entitled FROM play_purchase_ledger WHERE token_sha256=$1",tokenHash).Scan(&owner,&pkg,&product,&kind,&entitled)
  if err!=nil || owner!=req.UserID || pkg!=req.PackageName || product!=req.ProductID || kind!="product" || !entitled { writeJSON(w,403,map[string]string{"error":"no matching verified, entitled one-time purchase"}); return }
  action:="acknowledge"
  endpoint:="https://androidpublisher.googleapis.com/androidpublisher/v3/applications/"+url.PathEscape(req.PackageName)+"/purchases/products/"+url.PathEscape(req.ProductID)+"/tokens/"+url.PathEscape(req.PurchaseToken)+":acknowledge"
  if consume { action="consume"; endpoint="https://androidpublisher.googleapis.com/androidpublisher/v3/applications/"+url.PathEscape(req.PackageName)+"/purchases/products/"+url.PathEscape(req.ProductID)+"/tokens/"+url.PathEscape(req.PurchaseToken)+":consume" }
  httpReq,err:=http.NewRequestWithContext(ctx,http.MethodPost,endpoint,strings.NewReader(`{"developerPayload":"omni-cyber-lab"}`))
  if err!=nil { writeJSON(w,500,map[string]string{"error":"could not create Publisher API request"}); return }
  httpReq.Header.Set("Content-Type","application/json")
  resp,err:=s.googleClient.Do(httpReq); if err!=nil { writeJSON(w,502,map[string]string{"error":"Google Play action request failed; retry safely"}); return }
  defer resp.Body.Close(); _,_=io.Copy(io.Discard,io.LimitReader(resp.Body,64*1024))
  if resp.StatusCode!=http.StatusOK && resp.StatusCode!=http.StatusNoContent { writeJSON(w,502,map[string]string{"error":"Google Play rejected "+action+" request","publisherStatus":fmt.Sprint(resp.StatusCode)}); return }
  writeJSON(w,200,map[string]any{"success":true,"action":action,"message":"Google Play accepted the action for the verified purchase."})
 }
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
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer pingCancel()
	if err := db.Ping(pingCtx); err != nil { log.Fatalf("database is not reachable: %v", err) }
	s := &server{db:db, googleClient:oauth2.NewClient(context.Background(), jwtConfig.TokenSource(context.Background())), apiKey:[]byte(apiKey), allowedPackages:envSet("ALLOWED_PACKAGE_NAMES"), allowedProducts:envSet("ALLOWED_PRODUCT_IDS")}
	if len(s.allowedPackages)==0 || len(s.allowedProducts)==0 { log.Fatal("ALLOWED_PACKAGE_NAMES and ALLOWED_PRODUCT_IDS must be configured") }
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { if r.Method != http.MethodGet { writeJSON(w,405,map[string]string{"error":"GET required"}); return }; writeJSON(w,200,map[string]string{"status":"ok"}) })
	mux.HandleFunc("/v1/play/verify", s.verify)
	mux.HandleFunc("/v1/wallet/fulfill", s.fulfillWallet)
	mux.HandleFunc("/v1/wallet/spend", s.spendWallet)
	mux.HandleFunc("/v1/play/rtdn", s.rtdn)
	mux.HandleFunc("/v1/play/acknowledge", s.purchaseAction(false))
	mux.HandleFunc("/v1/play/consume", s.purchaseAction(true))
	port := os.Getenv("PORT"); if port=="" { port="8080" }
	srv := &http.Server{Addr:":"+port, Handler:mux, ReadHeaderTimeout:5*time.Second, ReadTimeout:10*time.Second, WriteTimeout:20*time.Second, IdleTimeout:60*time.Second}
	log.Printf("Play verifier listening on :%s", port)
	log.Fatal(srv.ListenAndServe())
}
