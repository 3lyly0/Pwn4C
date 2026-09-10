package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	xiaomiSalt    = "a2e112bcf13c71247c98f584f4dc494d"
	clientTimeout = 10 * time.Second
)

var (
	macRegex   = regexp.MustCompile(`(?i)(?:deviceId|mac)\s*[:=]\s*['"]([0-9a-fA-F:]{17})['"]`)
	nonceRegex = regexp.MustCompile(`(?i)(?:nonce|key)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]+)['"]`)
	stokRegex  = regexp.MustCompile(`stok=([a-zA-Z0-9]{32})`)
)

type InitData struct {
	MAC   string
	Nonce string
}

type LoginResponse struct {
	Code int    `json:"code"`
	URL  string `json:"url"`
	Msg  string `json:"msg,omitempty"`
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		slog.Error("missing target IP argument", "usage", fmt.Sprintf("%s <target_ip>", os.Args[0]))
		os.Exit(1)
	}

	targetIP := strings.TrimSpace(os.Args[1])
	client := &http.Client{
		Timeout: clientTimeout,
	}

	slog.Info("scraping initialization parameters", "target", targetIP)
	initData, err := scrapeInitData(client, targetIP)
	if err != nil {
		slog.Error("failed to retrieve initialization data", "error", err)
		os.Exit(1)
	}
	slog.Info("extracted router metadata", "mac", initData.MAC, "nonce", initData.Nonce)

	password, err := promptPassword()
	if err != nil {
		slog.Error("failed to read password", "error", err)
		os.Exit(1)
	}

	finalHash := generateXiaomiHash(password, initData.MAC, initData.Nonce)

	slog.Info("authenticating against router API")
	stok, err := authenticate(client, targetIP, initData.Nonce, finalHash)
	if err != nil {
		slog.Error("authentication failed", "error", err)
		os.Exit(1)
	}

	slog.Info("authentication successful", "stok", stok)
	fmt.Printf("[+] Administrative Session Token (stok): %s\n", stok)
}

func scrapeInitData(client *http.Client, targetIP string) (*InitData, error) {
	reqURL := fmt.Sprintf("http://%s/cgi-bin/luci/web", targetIP)
	resp, err := client.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", reqURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d from %s", resp.StatusCode, reqURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	bodyStr := string(body)

	macMatch := macRegex.FindStringSubmatch(bodyStr)
	if len(macMatch) < 2 {
		return nil, errors.New("unable to extract router MAC/deviceId from web response")
	}

	nonceMatch := nonceRegex.FindStringSubmatch(bodyStr)
	if len(nonceMatch) < 2 {
		return nil, errors.New("unable to extract authentication nonce/key from web response")
	}

	return &InitData{
		MAC:   macMatch[1],
		Nonce: nonceMatch[1],
	}, nil
}

func promptPassword() (string, error) {
	fmt.Print("Enter router admin password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytePassword)), nil
}

func generateXiaomiHash(password, mac, nonce string) string {
	key := mac + xiaomiSalt

	firstSum := sha1.Sum([]byte(password + key))
	firstHash := hex.EncodeToString(firstSum[:])

	finalSum := sha1.Sum([]byte(nonce + firstHash))
	return hex.EncodeToString(finalSum[:])
}

func authenticate(client *http.Client, targetIP, nonce, passwordHash string) (string, error) {
	loginURL := fmt.Sprintf("http://%s/cgi-bin/luci/api/xqsystem/login", targetIP)

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", passwordHash)
	form.Set("logtype", "2")
	form.Set("nonce", nonce)

	req, err := http.NewRequest(http.MethodPost, loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", loginURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading login response body: %w", err)
	}

	var loginResp LoginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return "", fmt.Errorf("unmarshaling login response JSON: %w (raw: %s)", err, string(body))
	}

	if loginResp.Code != 0 {
		return "", fmt.Errorf("login rejected by router (code=%d, msg=%q)", loginResp.Code, loginResp.Msg)
	}

	if loginResp.URL == "" {
		return "", fmt.Errorf("login response omitted redirection URL: %s", string(body))
	}

	stokMatch := stokRegex.FindStringSubmatch(loginResp.URL)
	if len(stokMatch) < 2 {
		return "", fmt.Errorf("stok token not found in redirection URL: %s", loginResp.URL)
	}

	return stokMatch[1], nil
}
