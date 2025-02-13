package testplugin

import (
    "context"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type SignatureGeneratorConfig struct {
    SecretClient string `json:"secretClient,omitempty"`
}

func SignatureGeneratorCreateConfig() *SignatureGeneratorConfig {
    return &SignatureGeneratorConfig{
        SecretClient: "Oj2eKc2nZwzTIRYBWEmOT4rKggn53meG", // Default secret
    }
}

type SignatureGenerator struct {
    next         http.Handler
    secretClient string
    name         string
}

func SignatureGeneratorNew(ctx context.Context, next http.Handler, config *SignatureGeneratorConfig, name string) (http.Handler, error) {
    return &SignatureGenerator{
        next:         next,
        secretClient: config.SecretClient,
        name:         name,
    }, nil
}

func (s *SignatureGenerator) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    // Capture the original response body
    body := &bytes.Buffer{}
    tee := io.TeeReader(req.Body, body)
    var tokenResponse map[string]interface{}

    if err := json.NewDecoder(tee).Decode(&tokenResponse); err != nil {
        http.Error(rw, "Invalid token response", http.StatusInternalServerError)
        return
    }

    // Extract the access token from the response
    accessToken, ok := tokenResponse["access_token"].(string)
    if !ok || accessToken == "" {
        http.Error(rw, "Missing access_token in response", http.StatusInternalServerError)
        return
    }

    // Generate the timestamp and signature
    timestamp := time.Now().Format(time.RFC3339)
    signature, err := s.calculateSignature(timestamp, accessToken)
    if err != nil {
        http.Error(rw, "Error calculating signature", http.StatusInternalServerError)
        return
    }

    // Attach the headers to the response
    rw.Header().Set("X-Guide", "python-anas-init") // Example guide value
    rw.Header().Set("X-Timestamp", timestamp)
    rw.Header().Set("X-Signature", signature)

    // Pass the request to the next handler with the original response body
    req.Body = ioutil.NopCloser(body)
    s.next.ServeHTTP(rw, req)
}

func (s *SignatureGenerator) calculateSignature(timestamp string, accessToken string) (string, error) {
    concatenatedString := s.secretClient + timestamp + accessToken
    normalizedString := removeAccents(strings.ToLower(concatenatedString))
    filteredString := filterString(normalizedString, "abcdefghijklmnopqrstuvwxyz0123456789-/.")

    hash := sha256.Sum256([]byte(filteredString))
    hexHash := hex.EncodeToString(hash[:])
    signature := base64.StdEncoding.EncodeToString([]byte(hexHash))

    return signature, nil
}