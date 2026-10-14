package awskmsemulator_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	awskmsemulator "github.com/blackwell-systems/aws-kms-emulator"
	"github.com/blackwell-systems/aws-kms-emulator/kmstest"
)

// call posts a raw AWS JSON 1.1 request and returns the status, headers and body.
func call(t *testing.T, url, target, body string, hdr map[string]string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	if target != "" {
		req.Header.Set("X-Amz-Target", "TrentService."+target)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func decodeError(t *testing.T, body string) (typ, msg string) {
	t.Helper()
	var e struct {
		Type    string `json:"__type"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("error body %q is not JSON: %v", body, err)
	}
	return e.Type, e.Message
}

func TestWire_SuccessShape(t *testing.T) {
	_, srv := newClient(t)
	status, hdr, body := call(t, srv.URL, "CreateKey", `{"KeySpec":"ECC_NIST_EDWARDS25519","KeyUsage":"SIGN_VERIFY"}`, nil)
	if status != 200 {
		t.Fatalf("status = %d, body %s", status, body)
	}
	if ct := hdr.Get("Content-Type"); ct != "application/x-amz-json-1.1" {
		t.Errorf("Content-Type = %q", ct)
	}
	if hdr.Get("x-amzn-RequestId") == "" {
		t.Error("missing x-amzn-RequestId")
	}
	var out struct {
		KeyMetadata map[string]any
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	// CreationDate is a JSON number of epoch seconds, as in the AWS JSON protocol.
	if _, ok := out.KeyMetadata["CreationDate"].(float64); !ok {
		t.Errorf("CreationDate = %#v, want a number", out.KeyMetadata["CreationDate"])
	}
	for _, f := range []string{"KeyId", "Arn", "KeySpec", "CustomerMasterKeySpec", "KeyUsage", "KeyState", "Enabled", "Origin", "KeyManager", "SigningAlgorithms", "AWSAccountId"} {
		if _, ok := out.KeyMetadata[f]; !ok {
			t.Errorf("KeyMetadata lacks %s", f)
		}
	}

	// Blobs are base64 strings.
	id := out.KeyMetadata["KeyId"].(string)
	status, _, body = call(t, srv.URL, "Sign", `{"KeyId":"`+id+`","Message":"`+base64.StdEncoding.EncodeToString([]byte("hi"))+`","SigningAlgorithm":"ED25519_SHA_512"}`, nil)
	if status != 200 {
		t.Fatalf("Sign status = %d, body %s", status, body)
	}
	var sig struct{ Signature string }
	_ = json.Unmarshal([]byte(body), &sig)
	if raw, err := base64.StdEncoding.DecodeString(sig.Signature); err != nil || len(raw) != 64 {
		t.Errorf("Signature = %q (%d bytes, %v); want 64 base64 bytes", sig.Signature, len(raw), err)
	}
}

func TestWire_EmptyResponseOperations(t *testing.T) {
	_, srv := newClient(t)
	_, _, body := call(t, srv.URL, "CreateKey", `{"KeySpec":"ECC_NIST_P256","KeyUsage":"SIGN_VERIFY"}`, nil)
	var out struct{ KeyMetadata struct{ KeyId string } }
	_ = json.Unmarshal([]byte(body), &out)
	for _, op := range []string{"DisableKey", "EnableKey"} {
		status, _, b := call(t, srv.URL, op, `{"KeyId":"`+out.KeyMetadata.KeyId+`"}`, nil)
		if status != 200 || b != "" {
			t.Errorf("%s = %d %q, want 200 with an empty body", op, status, b)
		}
	}
}

func TestWire_ErrorShape(t *testing.T) {
	_, srv := newClient(t)
	status, hdr, body := call(t, srv.URL, "DescribeKey", `{"KeyId":"alias/missing"}`, nil)
	if status != 400 {
		t.Errorf("status = %d, want 400", status)
	}
	if hdr.Get("x-amzn-ErrorType") != "NotFoundException" {
		t.Errorf("x-amzn-ErrorType = %q", hdr.Get("x-amzn-ErrorType"))
	}
	if hdr.Get("Content-Type") != "application/x-amz-json-1.1" || hdr.Get("x-amzn-RequestId") == "" {
		t.Errorf("headers = %v", hdr)
	}
	typ, msg := decodeError(t, body)
	if typ != "NotFoundException" || !strings.Contains(msg, "arn:aws:kms:us-east-1:111122223333:alias/missing") {
		t.Errorf("error body = %s", body)
	}
}

// The AWS SDKs validate required members before sending, so these only reach
// the server from other clients. The server must still reject them.
func TestWire_MissingRequiredMembers(t *testing.T) {
	_, srv := newClient(t)
	id := `"1234abcd-12ab-34cd-56ef-1234567890ab"`
	b64 := `"` + base64.StdEncoding.EncodeToString([]byte("x")) + `"`
	for name, tc := range map[string]struct{ op, body string }{
		"Sign without KeyId":                {"Sign", `{"Message":` + b64 + `,"SigningAlgorithm":"ECDSA_SHA_256"}`},
		"Sign without Message":              {"Sign", `{"KeyId":` + id + `,"SigningAlgorithm":"ECDSA_SHA_256"}`},
		"Sign with an empty body":           {"Sign", ``},
		"Sign without SigningAlgorithm":     {"Sign", `{"KeyId":` + id + `,"Message":` + b64 + `}`},
		"Verify without Signature":          {"Verify", `{"KeyId":` + id + `,"Message":` + b64 + `,"SigningAlgorithm":"ECDSA_SHA_256"}`},
		"Verify without Message":            {"Verify", `{"KeyId":` + id + `,"Signature":` + b64 + `,"SigningAlgorithm":"ECDSA_SHA_256"}`},
		"Verify without SigningAlgorithm":   {"Verify", `{"KeyId":` + id + `,"Message":` + b64 + `,"Signature":` + b64 + `}`},
		"DescribeKey without KeyId":         {"DescribeKey", `{}`},
		"GetPublicKey without KeyId":        {"GetPublicKey", `{}`},
		"EnableKey without KeyId":           {"EnableKey", `{}`},
		"DisableKey without KeyId":          {"DisableKey", `{}`},
		"ScheduleKeyDeletion without KeyId": {"ScheduleKeyDeletion", `{}`},
		"CancelKeyDeletion without KeyId":   {"CancelKeyDeletion", `{}`},
		"CreateAlias without AliasName":     {"CreateAlias", `{"TargetKeyId":` + id + `}`},
		"CreateAlias without TargetKeyId":   {"CreateAlias", `{"AliasName":"alias/x"}`},
		"DeleteAlias without AliasName":     {"DeleteAlias", `{}`},
		"TagResource without Tags":          {"TagResource", `{"KeyId":` + id + `}`},
		"UntagResource without TagKeys":     {"UntagResource", `{"KeyId":` + id + `}`},
		"ListResourceTags without KeyId":    {"ListResourceTags", `{}`},
		"PendingWindowInDays of 0":          {"ScheduleKeyDeletion", `{"KeyId":` + id + `,"PendingWindowInDays":0}`},
	} {
		t.Run(name, func(t *testing.T) {
			status, hdr, body := call(t, srv.URL, tc.op, tc.body, nil)
			typ, _ := decodeError(t, body)
			if status != 400 || typ != "ValidationException" || hdr.Get("x-amzn-ErrorType") != "ValidationException" {
				t.Fatalf("got %d %s (%s), want 400 ValidationException", status, typ, body)
			}
		})
	}
}

func TestWire_MalformedBodies(t *testing.T) {
	_, srv := newClient(t)
	for name, body := range map[string]string{
		"not JSON":                 `{"KeyId":`,
		"wrong type for a string":  `{"KeyId":42}`,
		"wrong type for Limit":     `{"Limit":"ten"}`,
		"invalid base64 in a blob": `{"KeyId":"k","Message":"***","SigningAlgorithm":"ECDSA_SHA_256"}`,
	} {
		op := "ListKeys"
		if strings.Contains(body, "Message") {
			op = "Sign"
		}
		status, _, b := call(t, srv.URL, op, body, nil)
		typ, _ := decodeError(t, b)
		if status != 400 || typ != "SerializationException" {
			t.Errorf("%s: %d %s, want 400 SerializationException", name, status, typ)
		}
	}
	// Members the API does not define are ignored, as AWS ignores them.
	if status, _, b := call(t, srv.URL, "ListKeys", `{"Limit":5,"FutureMember":{"a":1}}`, nil); status != 200 {
		t.Errorf("unknown member: %d %s", status, b)
	}
}

func TestWire_Dispatch(t *testing.T) {
	_, srv := newClient(t)
	for name, tc := range map[string]struct {
		target string
		raw    http.Header
		status int
		typ    string
	}{
		"unknown operation":       {target: "Frobnicate", status: 404, typ: "UnknownOperationException"},
		"implemented in AWS only": {target: "Encrypt", status: 501, typ: "NotImplementedException"},
		"GenerateDataKey":         {target: "GenerateDataKey", status: 501, typ: "NotImplementedException"},
		"no target":               {target: "", status: 404, typ: "UnknownOperationException"},
	} {
		status, hdr, body := call(t, srv.URL, tc.target, `{}`, nil)
		typ, _ := decodeError(t, body)
		if status != tc.status || typ != tc.typ || hdr.Get("x-amzn-ErrorType") != tc.typ {
			t.Errorf("%s: %d %s, want %d %s", name, status, typ, tc.status, tc.typ)
		}
	}
	// A target for another service is not a KMS operation.
	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{}`))
	req.Header.Set("X-Amz-Target", "DynamoDB_20120810.ListTables")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("foreign target: %d, want 404", resp.StatusCode)
	}
	// Only POST to / is KMS.
	for _, r := range []struct{ method, path string }{{"GET", "/"}, {"PUT", "/"}, {"POST", "/other"}} {
		req, _ := http.NewRequest(r.method, srv.URL+r.path, nil)
		req.Header.Set("X-Amz-Target", "TrentService.ListKeys")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("%s %s: %d, want 404", r.method, r.path, resp.StatusCode)
		}
	}
}

func TestWire_Health(t *testing.T) {
	_, srv := newClient(t)
	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET /health = %d", resp.StatusCode)
	}
}

func TestWire_RequestBodyLimit(t *testing.T) {
	_, srv := newClient(t)
	big := `{"Description":"` + strings.Repeat("x", 300<<10) + `"}`
	status, _, body := call(t, srv.URL, "CreateKey", big, nil)
	typ, _ := decodeError(t, body)
	if status != 413 || typ != "RequestEntityTooLargeException" {
		t.Fatalf("got %d %s, want 413 RequestEntityTooLargeException", status, typ)
	}
}

func TestAuth_DefaultAcceptsAnything(t *testing.T) {
	_, srv := newClient(t)
	if status, _, b := call(t, srv.URL, "ListKeys", `{}`, nil); status != 200 {
		t.Fatalf("an unauthenticated request must be accepted by default: %d %s", status, b)
	}
	if status, _, b := call(t, srv.URL, "ListKeys", `{}`, map[string]string{"Authorization": "garbage"}); status != 200 {
		t.Fatalf("a malformed Authorization header must be ignored by default: %d %s", status, b)
	}
}

func TestAuth_StrictMode(t *testing.T) {
	c, srv := newClient(t, awskmsemulator.WithStrictAuth(true))
	good := "AWS4-HMAC-SHA256 Credential=AKIA/20260101/us-east-1/kms/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcd"
	date := map[string]string{"X-Amz-Date": "20260101T000000Z"}
	with := func(auth string) map[string]string {
		h := map[string]string{"Authorization": auth}
		for k, v := range date {
			h[k] = v
		}
		return h
	}
	for name, tc := range map[string]struct {
		hdr    map[string]string
		status int
		typ    string
	}{
		"no Authorization":             {nil, 403, "MissingAuthenticationToken"},
		"wrong scheme":                 {with("Bearer abc"), 403, "IncompleteSignature"},
		"no Credential":                {with("AWS4-HMAC-SHA256 SignedHeaders=host, Signature=abcd"), 403, "IncompleteSignature"},
		"no SignedHeaders":             {with("AWS4-HMAC-SHA256 Credential=AKIA/20260101/us-east-1/kms/aws4_request, Signature=abcd"), 403, "IncompleteSignature"},
		"no Signature":                 {with("AWS4-HMAC-SHA256 Credential=AKIA/20260101/us-east-1/kms/aws4_request, SignedHeaders=host"), 403, "IncompleteSignature"},
		"scope of another service":     {with("AWS4-HMAC-SHA256 Credential=AKIA/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abcd"), 403, "IncompleteSignature"},
		"short scope":                  {with("AWS4-HMAC-SHA256 Credential=AKIA/kms, SignedHeaders=host, Signature=abcd"), 403, "IncompleteSignature"},
		"no date header":               {map[string]string{"Authorization": good}, 403, "IncompleteSignature"},
		"well-formed, wrong signature": {with(good), 200, ""},
	} {
		status, _, body := call(t, srv.URL, "ListKeys", `{}`, tc.hdr)
		if status != tc.status {
			t.Errorf("%s: status %d (%s), want %d", name, status, body, tc.status)
			continue
		}
		if tc.typ != "" {
			if typ, _ := decodeError(t, body); typ != tc.typ {
				t.Errorf("%s: %s, want %s", name, typ, tc.typ)
			}
		}
	}
	// The real SDK signs requests, so it passes strict mode.
	if _, err := c.CreateKey(context.Background(), &kms.CreateKeyInput{KeySpec: types.KeySpecEccNistP256, KeyUsage: types.KeyUsageTypeSignVerify}); err != nil {
		t.Fatalf("SigV4-signed SDK request rejected in strict mode: %v", err)
	}
}

func TestRegister_MountsOnMux(t *testing.T) {
	mux := http.NewServeMux()
	if err := awskmsemulator.Register(mux); err != nil {
		t.Fatal(err)
	}
	mux.HandleFunc("/other", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if status, _, b := call(t, srv.URL, "ListKeys", `{}`, nil); status != 200 {
		t.Fatalf("ListKeys via mux: %d %s", status, b)
	}
	resp, err := http.Get(srv.URL + "/other")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("other handler: %d", resp.StatusCode)
	}
}

func TestNew_IsolatedInstances(t *testing.T) {
	c1, _ := newClient(t)
	c2, _ := newClient(t)
	key := createKey(t, c1, types.KeySpecEccNistP256)
	_, err := c2.DescribeKey(context.Background(), &kms.DescribeKeyInput{KeyId: key.KeyId})
	wantCode(t, err, "NotFoundException")
}

func TestNew_FromEnv(t *testing.T) {
	t.Setenv(awskmsemulator.RegionEnv, "ap-south-1")
	t.Setenv(awskmsemulator.AccountIDEnv, "210987654321")
	t.Setenv(awskmsemulator.StrictAuthEnv, "true")
	h, err := awskmsemulator.New(awskmsemulator.FromEnv()...)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	if status, _, _ := call(t, srv.URL, "ListKeys", `{}`, nil); status != 403 {
		t.Fatalf("AWS_KMS_STRICT_AUTH=true did not enable strict mode: status %d", status)
	}
	hdr := map[string]string{
		"Authorization": "AWS4-HMAC-SHA256 Credential=A/20260101/ap-south-1/kms/aws4_request, SignedHeaders=host, Signature=s",
		"X-Amz-Date":    "20260101T000000Z",
	}
	_, _, body := call(t, srv.URL, "CreateKey", `{"KeySpec":"ECC_NIST_P256","KeyUsage":"SIGN_VERIFY"}`, hdr)
	if !strings.Contains(body, "arn:aws:kms:ap-south-1:210987654321:key/") {
		t.Fatalf("ARN does not use the configured Region and account: %s", body)
	}
}

func TestWithLogf_OneLinePerRequest(t *testing.T) {
	var lines []string
	srv := kmstest.NewServer(t, awskmsemulator.WithLogf(func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}))
	c := srv.Client()
	_, _ = c.DescribeKey(context.Background(), &kms.DescribeKeyInput{KeyId: aws.String("alias/none")})
	_, _ = c.ListKeys(context.Background(), &kms.ListKeysInput{})
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "DescribeKey -> NotFoundException") || lines[1] != "ListKeys -> ok" {
		t.Fatalf("log lines = %q", lines)
	}
}

func TestKMSTest_ConfigBuildsAWorkingClient(t *testing.T) {
	srv := kmstest.NewServer(t)
	c := kms.NewFromConfig(srv.Config())
	if _, err := c.CreateKey(context.Background(), &kms.CreateKeyInput{}); err != nil {
		t.Fatalf("a client built from kmstest.Server.Config: %v", err)
	}
}
