package passwordgenerator

import (
	"encoding/json"
	"net/http"

	"headeranalyzer/security"
)

var validator = security.NewInputValidator()

// PasswordAPIHandler handles password generation requests
func PasswordAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var requestData struct {
		Type           string `json:"type"`
		Length         int    `json:"length"`
		IncludeUpper   bool   `json:"includeUpper"`
		IncludeLower   bool   `json:"includeLower"`
		NumberCount    int    `json:"numberCount"`
		SpecialChars   string `json:"specialChars"`
		NoConsecutive  bool   `json:"noConsecutive"`
		WordCount      int    `json:"wordCount"`
		NumberPosition string `json:"numberPosition"`
		UseNumbers     bool   `json:"useNumbers"`
		UseSpecial     bool   `json:"useSpecial"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid JSON"))
		return
	}

	// Validate input parameters
	if requestData.Length < 4 || requestData.Length > 128 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Length must be between 4 and 128"))
		return
	}

	if requestData.NumberCount < 0 || requestData.NumberCount > 20 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Number count must be between 0 and 20"))
		return
	}

	if requestData.WordCount < 2 || requestData.WordCount > 10 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Word count must be between 2 and 10"))
		return
	}

	if len(requestData.SpecialChars) > 50 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Special characters string too long"))
		return
	}

	// Validate type parameter
	if requestData.Type != "random" && requestData.Type != "passphrase" {
		requestData.Type = "passphrase" // Default to passphrase
	}

	// Validate number position
	validPositions := map[string]bool{"start": true, "end": true, "each": true}
	if !validPositions[requestData.NumberPosition] {
		requestData.NumberPosition = "end" // Default
	}

	// Sanitize special characters to prevent potential issues
	requestData.SpecialChars = validator.SanitizeHTML(requestData.SpecialChars)

	// Convert to internal Config format
	config := Config{
		Length:               requestData.Length,
		IncludeUpper:         requestData.IncludeUpper,
		IncludeLower:         requestData.IncludeLower,
		NumberCount:          requestData.NumberCount,
		SpecialChars:         requestData.SpecialChars,
		NoConsecutive:        requestData.NoConsecutive,
		UsePassphrase:        requestData.Type == "passphrase",
		WordCount:            requestData.WordCount,
		NumberPosition:       requestData.NumberPosition,
		PassphraseUseNumbers: requestData.UseNumbers,
		PassphraseUseSpecial: requestData.UseSpecial,
	}

	password, err := GeneratePassword(config)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(password))
}

// PasswordInfoAPIHandler handles word list info requests
func PasswordInfoAPIHandler(w http.ResponseWriter, r *http.Request) {
	count, source, lastUpdate := GetWordListInfo()

	info := map[string]interface{}{
		"wordCount":  count,
		"source":     source,
		"lastUpdate": lastUpdate.Format("2006-01-02 15:04:05"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}
