package testplugin

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "net/http"
    "strings"
    "time"

    "github.com/othmane222/testplugin"
)

// Config holds the plugin configuration
type Config struct {
    SecretKey string `json:"secretKey,omitempty"`
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
    return &Config{
        SecretKey: "Oj2eKc2nZwzTIRYBWEmOT4rKggn53meG", // Default secret key
    }
}

// SignatureVerifier represents the middleware
type SignatureVerifier struct {
    next       http.Handler
    secretKey  string
    name       string
    sigHeader  string
    dateHeader string
}

// New creates a new instance of the plugin middleware
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
    return &SignatureVerifier{
        next:       next,
        secretKey:  config.SecretKey,
        name:       name,
        sigHeader:  "X-Request-Signature",
        dateHeader: "X-Date",
    }, nil
}

// ServeHTTP implements the http.Handler interface
func (s *SignatureVerifier) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    // Extract required headers
    token := extractTokenFromAuthHeader(req.Header.Get("Authorization"))
    timestamp := req.Header.Get(s.dateHeader)
    signature := req.Header.Get(s.sigHeader)

    // Validate headers
    if token == "" || timestamp == "" || signature == "" {
        http.Error(rw, "Missing required headers", http.StatusBadRequest)
        fmt.Fprintln(rw, "Required headers: Authorization, X-Date, X-Request-Signature")
        return
    }

    // Parse timestamp
    parsedTime, err := time.Parse(time.RFC1123, timestamp)
    if err != nil {
        http.Error(rw, "Invalid date format", http.StatusBadRequest)
        fmt.Fprintln(rw, "X-Date must be in RFC1123 format (e.g., Fri, 14 Feb 2025 11:20:00 GMT)")
        return
    }

    // Check if timestamp is within allowed range (e.g., ±1 minute)
    if !parsedTime.Add(1 * time.Minute).After(time.Now()) || !parsedTime.Add(-1*time.Minute).Before(time.Now()) {
        http.Error(rw, "Expired timestamp", http.StatusUnauthorized)
        fmt.Fprintln(rw, "X-Date timestamp must be within ±1 minute of the current time")
        return
    }

    // Compute expected signature
    expectedSig, err := s.computeSignature(token, timestamp)
    if err != nil {
        http.Error(rw, "Error computing signature", http.StatusInternalServerError)
        fmt.Fprintln(rw, err)
        return
    }

    // Verify signature
    if strings.ToLower(signature) != strings.ToLower(expectedSig) {
        http.Error(rw, "Invalid signature", http.StatusUnauthorized)
        fmt.Fprintln(rw, "Provided signature does not match the expected value")
        return
    }

    // Pass the request to the next handler
    s.next.ServeHTTP(rw, req)
}

// Helper function to extract the token from the Authorization header
func extractTokenFromAuthHeader(header string) string {
    if header == "" || !strings.HasPrefix(header, "Bearer ") {
        return ""
    }
    return strings.TrimPrefix(header, "Bearer ")
}

// Helper function to compute the signature
func (s *SignatureVerifier) computeSignature(token, timestamp string) (string, error) {
    // Concatenate data: token + timestamp + secretKey
    data := fmt.Sprintf("%s%s%s", token, timestamp, s.secretKey)

    // Compute SHA-256 hash
    hash := sha256.Sum256([]byte(data))

    // Convert hash to hexadecimal representation
    hexSig := hex.EncodeToString(hash[:])

    // Encode as Base64 (optional, depending on your needs)
    base64Sig := base64.StdEncoding.EncodeToString([]byte(hexSig))

    return base64Sig, nil
}