package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
    // Initialize Redis client
    redisClient := redis.NewClient(&redis.Options{
        Addr:     "localhost:6379", // Replace with your Redis address
        Password: "",               // No password by default
        DB:       0,                // Use default DB
    })

    // Start the HTTP server
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        key := generateCacheKey(r)

        // Check if the response exists in Redis
        val, err := redisClient.Get(ctx, key).Result()
        if err == redis.Nil {
            // Cache miss: Fetch from backend and cache the response
            log.Printf("Cache miss for key: %s", key)
            cacheMissHandler(w, r, redisClient, key)
        } else if err != nil {
            // Error fetching from Redis
            log.Printf("Error fetching from Redis: %v", err)
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        } else {
            // Cache hit: Serve the cached response
            log.Printf("Cache hit for key: %s", key)
            w.Header().Set("X-Cache", "HIT")
            w.Write([]byte(val))
        }
    })

    log.Println("Starting middleware service on :8080...")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func cacheMissHandler(w http.ResponseWriter, r *http.Request, redisClient *redis.Client, key string) {
    // Forward the request to the backend service
    resp, err := http.DefaultTransport.RoundTrip(r)
    if err != nil {
        http.Error(w, "Failed to fetch from backend", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    // Read the response body
    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        http.Error(w, "Failed to read response body", http.StatusInternalServerError)
        return
    }

    // Cache the response in Redis
    err = redisClient.Set(ctx, key, string(bodyBytes), time.Hour).Err()
    if err != nil {
        log.Printf("Error caching response: %v", err)
    }

    // Copy the response to the client
    for k, vv := range resp.Header {
        for _, v := range vv {
            w.Header().Add(k, v)
        }
    }
    w.WriteHeader(resp.StatusCode)
    w.Write(bodyBytes)
}

func generateCacheKey(r *http.Request) string {
    return fmt.Sprintf("%s:%s", r.Method, r.URL.String())
}