package main

// Load the required libraries
import (
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// Hash struct
type HashRequest struct {
	Password string `json:"password"`
}

type HashResponse struct {
	Hash string `json:"hash"`
}

// Verify struct
type VerifyRequest struct {
	Password string `json:"password"`
	Hash     string `json:"hash"`
}

type VerifyResponse struct {
	Match bool `json:"valid"`
}

// HashPassword using bcrypt
func HashPassword(w http.ResponseWriter, r *http.Request) {
	var req HashRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	res := HashResponse{Hash: string(hash)}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// VerifyPassword using bcrypt
func VerifyPassword(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(req.Hash), []byte(req.Password))
	if err != nil {
		http.Error(w, "Password does not match hash", http.StatusUnauthorized)
		return
	}

	res := VerifyResponse{Match: true}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func main() {
	http.HandleFunc("/hash", HashPassword)
	http.HandleFunc("/verify", VerifyPassword)

	log.Println("Microservice running on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
