package passwordgenerator

import (
	"encoding/json"
	"net/http"
)

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
