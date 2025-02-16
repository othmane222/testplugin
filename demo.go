package testplugin

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "net/http"
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
    // Extract required headers
    guide := req.Header.Get("X-Guide")
    timestamp := req.Header.Get("X-Timestamp")
    signature := req.Header.Get("X-Signature")
    authorization := req.Header.Get("Authorization")

    if guide == "" || timestamp == "" || signature == "" || authorization == "" {
        http.Error(rw, "Missing required headers", http.StatusBadRequest)
        return
    }

    // Extract token from Authorization header
    token := strings.TrimPrefix(authorization, "Bearer ")
    if !strings.HasPrefix(authorization, "Bearer ") || token == "" {
        http.Error(rw, "Invalid Authorization header", http.StatusBadRequest)
        return
    }

    // Calculate expected signature
    expectedSignature, err := s.calculateSignature(guide, timestamp, token)
    if err != nil {
        http.Error(rw, "Error calculating signature", http.StatusInternalServerError)
        return
    }

    // Log the expected signature for debugging
    logging.Infof("Expected Signature: %s", expectedSignature)

    // Validate the signature
    if signature != expectedSignature {
        http.Error(rw, "Invalid signature", http.StatusUnauthorized)
        return
    }

    // Pass the request to the next handler
    s.next.ServeHTTP(rw, req)
}

// calculateSignature computes the SHA-256 hash and encodes it as Base64
func (s *SignatureVerifier) calculateSignature(guide, timestamp, token string) (string, error) {
    allowedChars := "abcdefghijklmnopqrstuvwxyz0123456789-/."

    // Concatenate data: guide + timestamp + token + secretClient
    concatenatedString := guide + timestamp + token + s.secretClient

    // Log the concatenated string for debugging
    logging.Infof("Concatenated String: %s", concatenatedString)

    // Normalize concatenated string
    normalizedString := removeAccents(strings.ToLower(concatenatedString))
    filteredString := filterString(normalizedString, allowedChars)

    // Log the normalized and filtered string for debugging
    logging.Infof("Normalized String: %s", normalizedString)
    logging.Infof("Filtered String: %s", filteredString)

    // Compute SHA-256 hash
    hash := sha256.Sum256([]byte(filteredString))
    hexHash := hex.EncodeToString(hash[:])

    // Log the hex hash for debugging
    logging.Infof("Hex Hash: %s", hexHash)

    // Encode as Base64
    signature := base64.StdEncoding.EncodeToString([]byte(hexHash))

    // Log the final Base64 signature for debugging
    logging.Infof("Base64 Signature: %s", signature)

    return signature, nil
}

// Helper functions

// removeAccents removes accented characters from a string
func removeAccents(s string) string {
    return strings.Map(func(r rune) rune {
        switch {
        case unicode.Is(unicode.Mn, r): // Remove diacritics
            return -1
        default:
            return r
        }
    }, s)
}

// filterString filters a string to allow only specific characters
func filterString(s string, allowed string) string {
    var result strings.Builder
    for _, c := range s {
        if strings.ContainsRune(allowed, c) {
            result.WriteRune(c)
        }
    }
    return result.String()
}