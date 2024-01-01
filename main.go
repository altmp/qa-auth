package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

var (
	discordBotToken     = ""
	discordClientID     = ""
	discordClientSecret = ""
	guildID             = ""
	cfSecurityToken     = ""
)

var rolesArr []string
var guildsArr []string

var (
	postURL = "https://qa-cdn.altmp.workers.dev/new-token"
)

type userInfo struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Discrim  string   `json:"discriminator"`
	Roles    []string `json:"roles"`
}

type response struct {
	Token string `json:"token"`
}

func main() {
	godotenv.Load()

	discordBotToken = os.Getenv("DISCORD_BOT_TOKEN")
	guildsArr = strings.Split(os.Getenv("DISCORD_GUILDS"), ",")
	fmt.Println(guildsArr)
	rolesArr = strings.Split(os.Getenv("DISCORD_QA_ROLES"), ",")
	fmt.Println(rolesArr)
	cfSecurityToken = os.Getenv("CF_SECURITY_TOKEN")
	discordClientID = os.Getenv("DISCORD_CLIENT_ID")
	discordClientSecret = os.Getenv("DISCORD_CLIENT_SECRET")
	host := os.Getenv("HTTP_HOST")
	port := os.Getenv("HTTP_PORT")

	http.HandleFunc("/auth", checkRoleHandler)

	log.Println("Server started on http://" + host + ":" + port)
	log.Fatal(http.ListenAndServe(host+":"+port, nil))
}

func checkRoleHandler(w http.ResponseWriter, r *http.Request) {
	code := r.Header.Get("Authorization")
	if code == "" {
		http.Error(w, "Access token not provided", http.StatusBadRequest)
		return
	}

	accessToken, err := exchangeCodeForToken(code)

	if err != nil {
		http.Error(w, "Failed to exchange code for access_token", http.StatusInternalServerError)
		return
	}

	user, err := getUserInfo(accessToken)
	if err != nil {
		http.Error(w, "Failed to retrieve user information", http.StatusInternalServerError)
		return
	}

	hasRole := false
	// Check if the user has the specified role in the guild
	for _, guild := range guildsArr {
		fmt.Println("Checking guild " + guild)
		tmpHasRole, err := checkUserRole(user.ID, guild)
		if err != nil {
			http.Error(w, "Failed to check user role", http.StatusInternalServerError)
			return
		}
		if tmpHasRole {
			hasRole = true
		}
	}

	fmt.Println(hasRole)

	if !hasRole {
		http.Error(w, "User does not have the required role", http.StatusForbidden)
		return
	}

	// Generate a random string
	randomString := generateRandomString(32)

	// Make a POST request with the random string in the body
	postData := map[string]string{"new_token": randomString}
	postJSON, _ := json.Marshal(postData)

	req, err := http.NewRequest("POST", postURL, bytes.NewBuffer(postJSON))
	if err != nil {
		http.Error(w, "Failed to create POST request", http.StatusInternalServerError)
		return
	}

	// Set the "Security" header
	req.Header.Set("Security", cfSecurityToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to make POST request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "POST request failed", resp.StatusCode)
		return
	}

	responseData := response{Token: randomString}

	responseJSON, err := json.Marshal(responseData)
	if err != nil {
		http.Error(w, "Failed to generate response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseJSON)
}

func exchangeCodeForToken(code string) (string, error) {
	clientID := discordClientID
	clientSecret := discordClientSecret
	authCode := code

	// Prepare the request body
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", authCode)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	fmt.Println(authCode)
	fmt.Println(clientID)
	fmt.Println(clientSecret)

	// Create a new HTTP client
	client := &http.Client{}

	// Create a new request
	req, err := http.NewRequest("POST", "https://discord.com/api/v10/oauth2/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	// Set the Content-Type header
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return "", err
	}

	// Read the response body
	// Assuming the response body is in JSON format
	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}

	// Decode the JSON response body into the result struct
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	return result.AccessToken, nil
}

func getUserInfo(accessToken string) (*userInfo, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://discord.com/api/v10/users/@me", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve user information: %s", resp.Status)
	}

	var user userInfo

	err = json.NewDecoder(resp.Body).Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func checkUserRole(userID string, guildID string) (bool, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://discord.com/api/v10/guilds/%s/members/%s", guildID, userID), nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "Bot "+discordBotToken)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var member struct {
		Roles []string `json:"roles"`
	}

	err = json.NewDecoder(resp.Body).Decode(&member)
	if err != nil {
		return false, err
	}

	for _, role := range member.Roles {
		for _, neededRole := range rolesArr {
			if role == neededRole {
				return true, nil
			}
		}
	}

	return false, nil
}

func generateRandomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}
