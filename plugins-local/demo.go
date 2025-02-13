// Package signatureverifier is a Traefik middleware plugin that verifies request signatures
package testplugin

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
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
        SecretClient: "Oj2eKc2nZwzTIRYBWEmOT4rKggn53meG", // Your default secret
    }
}

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

func (s *SignatureVerifier) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    guide := req.Header.Get("X-Guide")
    timestamp := req.Header.Get("X-Timestamp")
    signature := req.Header.Get("X-Signature")

    if guide == "" || timestamp == "" || signature == "" {
        http.Error(rw, "Missing required headers", http.StatusBadRequest)
        return
    }

    // Parse request body
    var requestData map[string]interface{}
    if req.Body != nil {
        if err := json.NewDecoder(req.Body).Decode(&requestData); err != nil {
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

    if signature != expectedSignature {
        http.Error(rw, "Invalid signature", http.StatusUnauthorized)
        return
    }

    s.next.ServeHTTP(rw, req)
}

func (s *SignatureVerifier) calculateSignature(guide string, timestamp string, requestData map[string]interface{}) (string, error) {
    // Extract values from request data
    values := extractValues(requestData)
    
    // Concatenate strings
    allowedChars := "abcdefghijklmnopqrstuvwxyz0123456789-/."
    concatenatedString := guide + timestamp + strings.Join(values, "")
    
    // Normalize string
    normalizedString := removeAccents(strings.ToLower(concatenatedString))
    filteredString := filterString(normalizedString, allowedChars)
    
    // Calculate SHA-256 hash
    hash := sha256.Sum256([]byte(filteredString))
    hexHash := hex.EncodeToString(hash[:])
    
    // Convert to base64
    signature := base64.StdEncoding.EncodeToString([]byte(hexHash))
    return signature, nil
}

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