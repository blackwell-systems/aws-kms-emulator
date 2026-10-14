package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestBinary builds the server, runs it with persistence on, signs through the
// AWS SDK, stops it with SIGTERM and checks that the key is still there when it
// starts again.
func TestBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals")
	}
	bin := filepath.Join(t.TempDir(), "server")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	dataDir := t.TempDir()
	port := freePort(t)

	start := func() (*exec.Cmd, *bytes.Buffer) {
		var logs bytes.Buffer
		cmd := exec.Command(bin, "--log-level", "debug")
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("AWS_KMS_PORT=%d", port), "AWS_KMS_DATA_DIR="+dataDir, "AWS_KMS_ACCOUNT_ID=555566667777")
		cmd.Stderr, cmd.Stdout = &logs, &logs
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		url := fmt.Sprintf("http://127.0.0.1:%d", port)
		deadline := time.Now().Add(10 * time.Second)
		for {
			resp, err := http.Get(url + "/health")
			if err == nil {
				resp.Body.Close()
				return cmd, &logs
			}
			if time.Now().After(deadline) {
				cmd.Process.Kill()
				t.Fatalf("server did not become ready: %v\n%s", err, logs.String())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	stop := func(cmd *exec.Cmd) {
		t.Helper()
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("server exited with %v after SIGTERM", err)
			}
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			t.Fatal("server did not stop after SIGTERM")
		}
	}
	client := kms.New(kms.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(fmt.Sprintf("http://127.0.0.1:%d", port)),
		Credentials:  credentials.NewStaticCredentialsProvider("a", "b", ""),
	})

	ctx := context.Background()
	cmd, logs := start()
	key, err := client.CreateKey(ctx, &kms.CreateKeyInput{KeySpec: types.KeySpecEccNistEdwards25519, KeyUsage: types.KeyUsageTypeSignVerify})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if want := "arn:aws:kms:us-east-1:555566667777:key/"; (*key.KeyMetadata.Arn)[:len(want)] != want {
		t.Errorf("Arn %s ignores AWS_KMS_ACCOUNT_ID", *key.KeyMetadata.Arn)
	}
	if _, err := client.Sign(ctx, &kms.SignInput{KeyId: key.KeyMetadata.KeyId, Message: []byte("m"), SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	stop(cmd)
	if !bytes.Contains(logs.Bytes(), []byte("CreateKey -> ok")) {
		t.Errorf("--log-level debug did not log requests:\n%s", logs.String())
	}

	cmd, _ = start()
	defer stop(cmd)
	if _, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: key.KeyMetadata.KeyId}); err != nil {
		t.Fatalf("the key did not survive a restart with AWS_KMS_DATA_DIR set: %v", err)
	}
}
