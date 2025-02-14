package testplugin

import (
    "bytes"       // Added for NewBuffer
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"          // Required for ReadAll and NopCloser
    "net/http"
    "sort"
    "strings"
    "unicode"
)

// Config holds the plugin configuration
type Config struct {
    SecretClient string `json:"secretClient,omitempty"`
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
    return &Config{
        SecretClient: "Oj2eKc2nZwzTIRYBWEmOT4rKggn53meG", // Default secret
    }
}

// SignatureVerifier represents the middleware
type SignatureVerifier struct {
    next         http.Handler
    secretClient string
    name         string
}

// New creates a new signature verification middleware
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
    return &SignatureVerifier{
        next:         next,
        secretClient: config.SecretClient,
        name:         name,
    }, nil
}

// ServeHTTP implements the http.Handler interface
func (s *SignatureVerifier) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    // Extract headers
    guide := req.Header.Get("X-Guide")
    timestamp := req.Header.Get("X-Timestamp")
    signature := req.Header.Get("X-Signature")

    if guide == "" || timestamp == "" || signature == "" {
        http.Error(rw, "Missing required headers", http.StatusBadRequest)
        return
    }

    // Parse request body only if it exists and the method allows it
    var requestData map[string]interface{}
    if req.Method == http.MethodPost || req.Method == http.MethodPut {
        defer req.Body.Close()
        bodyBytes, err := io.ReadAll(req.Body) // Requires 'io' package
        if err != nil {
            http.Error(rw, "Error reading request body", http.StatusBadRequest)
            return
        }

        // Reset the body so it can be passed downstream
        req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Requires 'bytes' package

        // Decode the body into a map
        if err := json.Unmarshal(bodyBytes, &requestData); err != nil {
            http.Error(rw, "Invalid request body", http.StatusBadRequest)
            return
        }
    }

    // Calculate expected signature
    expectedSignature, err := s.calculateSignature(guide, timestamp, requestData)
    if err != nil {
        http.Error(rw, "Error calculating signature", http.StatusInternalServerError)
        return
    }

    // Validate the signature
    if signature != expectedSignature {
        http.Error(rw, "Invalid signature", http.StatusUnauthorized)
        return
    }

    // Pass the request to the next handler
    s.next.ServeHTTP(rw, req)
}

// calculateSignature computes the SHA-256 hash and encodes it as Base64
func (s *SignatureVerifier) calculateSignature(guide, timestamp string, requestData map[string]interface{}) (string, error) {
    values := extractValues(requestData)
    allowedChars := "abcdefghijklmnopqrstuvwxyz0123456789-/."
    concatenatedString := guide + timestamp + strings.Join(values, "")

    normalizedString := removeAccents(strings.ToLower(concatenatedString))
    filteredString := filterString(normalizedString, allowedChars)

    hash := sha256.Sum256([]byte(filteredString))
    hexHash := hex.EncodeToString(hash[:])
    signature := base64.StdEncoding.EncodeToString([]byte(hexHash))

    return signature, nil
}

// Helper functions
func extractValues(data interface{}) []string {
    var values []string

    switch v := data.(type) {
    case map[string]interface{}:
        keys := make([]string, 0, len(v))
        for k := range v {
            keys = append(keys, k)
        }
        sort.Strings(keys)

        for _, k := range keys {
            values = append(values, extractValues(v[k])...)
        }
    case []interface{}:
        for _, item := range v {
            values = append(values, extractValues(item)...)
        }
    default:
        if v != nil {
            values = append(values, fmt.Sprint(v))
        }
    }

    return values
}

func removeAccents(s string) string {
    return strings.Map(func(r rune) rune {
        switch {
        case unicode.Is(unicode.Mn, r):
            return -1
        default:
            return r
        }
    }, s)
}

func filterString(s string, allowed string) string {
    var result strings.Builder
    for _, c := range s {
        if strings.ContainsRune(allowed, c) {
            result.WriteRune(c)
        }
    }
    return result.String()
}