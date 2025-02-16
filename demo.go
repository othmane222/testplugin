package testplugin

import (
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "strings"
    "time"
    "unicode"
)

func main() {
    // Test values
    guide := "test-guide"
    token := "your-bearer-token"
    timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
    secretClient := "Oj2eKc2nZwzTIRYBWEmOT4rKggn53meG"

    // Calculate signature
    signature, _ := calculateSignature(guide, timestamp, token, secretClient)

    fmt.Printf("Guide: %s\n", guide)
    fmt.Printf("Timestamp: %s\n", timestamp)
    fmt.Printf("Token: %s\n", token)
    fmt.Printf("Calculated Signature: %s\n", signature)
    fmt.Printf("\nCURL command to test:\n")
    fmt.Printf("curl -X GET 'your-endpoint' \\\n")
    fmt.Printf("  -H 'Authorization: Bearer %s' \\\n", token)
    fmt.Printf("  -H 'X-Guide: %s' \\\n", guide)
    fmt.Printf("  -H 'X-Timestamp: %s' \\\n", timestamp)
    fmt.Printf("  -H 'X-Signature: %s'\n", signature)
}

func calculateSignature(guide, timestamp, token, secretClient string) (string, error) {
    allowedChars := "abcdefghijklmnopqrstuvwxyz0123456789-/."

    // Concatenate data: guide + timestamp + token + secretClient
    concatenatedString := guide + timestamp + token + secretClient

    // Normalize concatenated string
    normalizedString := removeAccents(strings.ToLower(concatenatedString))
    filteredString := filterString(normalizedString, allowedChars)

    // Compute SHA-256 hash
    hash := sha256.Sum256([]byte(filteredString))
    hexHash := hex.EncodeToString(hash[:])

    // Encode as Base64
    signature := base64.StdEncoding.EncodeToString([]byte(hexHash))

    return signature, nil
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