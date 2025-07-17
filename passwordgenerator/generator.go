package passwordgenerator

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Length               int    `json:"length"`
	IncludeUpper         bool   `json:"includeUpper"`
	IncludeLower         bool   `json:"includeLower"`
	NumberCount          int    `json:"numberCount"`
	SpecialChars         string `json:"specialChars"`
	NoConsecutive        bool   `json:"noConsecutive"`
	UsePassphrase        bool   `json:"usePassphrase"`
	WordCount            int    `json:"wordCount"`
	NumberPosition       string `json:"numberPosition"` // "start", "end", "each"
	PassphraseUseNumbers bool   `json:"passphraseUseNumbers"`
	PassphraseUseSpecial bool   `json:"passphraseUseSpecial"`
}

// Fallback word list in case online fetch fails
var fallbackWordList = []string{
	"apple", "brave", "chair", "dance", "eagle", "flame", "grape", "happy", "island", "jungle",
	"kite", "lemon", "magic", "night", "ocean", "piano", "quiet", "river", "storm", "tiger",
	"under", "voice", "water", "young", "zebra", "beach", "cloud", "dream", "fresh", "glass",
	"heart", "light", "money", "paper", "quick", "royal", "smile", "table", "violet", "world",
	"bright", "castle", "gentle", "honest", "knight", "marble", "orange", "purple", "silver", "yellow",
	"ancient", "crystal", "distant", "emerald", "fantasy", "harmony", "journey", "mystery", "outdoor", "perfect",
	"rainbow", "serenity", "thunder", "universe", "victory", "whisper", "amazing", "balance", "courage", "dignity",
	"elegant", "freedom", "golden", "holiday", "inspire", "justice", "kindness", "library", "mountain", "natural",
	"peaceful", "quality", "respect", "sunshine", "triumph", "unique", "wonderful", "adventure", "beautiful", "creative",
	"delicate", "exciting", "friendly", "generous", "hilarious", "incredible", "joyful", "lovely", "magnificent", "optimistic",
}

// Global word list cache
var (
	wordList     []string
	wordListMux  sync.RWMutex
	lastFetch    time.Time
	fetchTimeout = 10 * time.Second
	cacheExpiry  = 24 * time.Hour // Cache for 24 hours
	wordListFile = "wordlist.txt" // Local file path
)

// InitWordList initializes the word list cache. Call this at app startup.
func InitWordList() {
	go func() {
		// Fetch word list in background to warm up cache
		getWordList()
	}()
}

// GetWordListInfo returns information about the current word list
func GetWordListInfo() (count int, source string, lastUpdate time.Time) {
	wordListMux.RLock()
	defer wordListMux.RUnlock()

	count = len(wordList)
	if count == 0 {
		count = len(fallbackWordList)
		source = "fallback"
		return
	}

	// Check if we have a local file
	if _, err := os.Stat(wordListFile); err == nil {
		fileTime := getFileModTime(wordListFile)
		if time.Since(fileTime) > cacheExpiry {
			source = "local file (expired)"
		} else if len(wordList) > len(fallbackWordList) {
			source = "local file (from MIT)"
		} else {
			source = "local file"
		}
		return count, source, fileTime
	}

	if time.Since(lastFetch) > cacheExpiry {
		source = "cached (expired)"
	} else if len(wordList) > len(fallbackWordList) {
		source = "MIT online"
	} else {
		source = "fallback"
	}

	return count, source, lastFetch
}

// getWordList returns the current word list, fetching from online source if needed
func getWordList() []string {
	wordListMux.RLock()

	// Check if we have a cached word list that's still valid
	if len(wordList) > 0 && time.Since(lastFetch) < cacheExpiry {
		defer wordListMux.RUnlock()
		return wordList
	}
	wordListMux.RUnlock()

	// Need to fetch or refresh
	wordListMux.Lock()
	defer wordListMux.Unlock()

	// Double-check in case another goroutine already fetched
	if len(wordList) > 0 && time.Since(lastFetch) < cacheExpiry {
		return wordList
	}

	// First try to load from local file
	if localWords, err := loadWordListFromFile(); err == nil && len(localWords) >= 100 {
		wordList = localWords
		lastFetch = getFileModTime(wordListFile)
		return wordList
	}

	// If local file doesn't exist or is invalid, try to fetch from MIT
	newWordList, err := fetchWordListFromMIT()
	if err != nil || len(newWordList) < 100 { // Sanity check
		// Use fallback if fetch failed or list is too small
		if len(wordList) == 0 {
			wordList = make([]string, len(fallbackWordList))
			copy(wordList, fallbackWordList)
		}
		return wordList
	}

	// Save downloaded word list to local file
	saveWordListToFile(newWordList)

	wordList = newWordList
	lastFetch = time.Now()
	return wordList
}

// loadWordListFromFile loads the word list from local file
func loadWordListFromFile() ([]string, error) {
	file, err := os.Open(wordListFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if len(word) > 0 && len(word) <= 15 {
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return words, nil
}

// saveWordListToFile saves the word list to local file
func saveWordListToFile(words []string) error {
	file, err := os.Create(wordListFile)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, word := range words {
		if _, err := fmt.Fprintln(file, word); err != nil {
			return err
		}
	}

	return nil
}

// getFileModTime returns the modification time of a file
func getFileModTime(filename string) time.Time {
	if info, err := os.Stat(filename); err == nil {
		return info.ModTime()
	}
	return time.Time{}
}

// fetchWordListFromMIT fetches the word list from MIT's server
// fetchWordListFromMIT fetches the word list from MIT's server
func fetchWordListFromMIT() ([]string, error) {
	client := &http.Client{
		Timeout: fetchTimeout,
	}

	resp, err := client.Get("https://www.mit.edu/~ecprice/wordlist.10000")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch word list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var words []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if len(word) > 0 && len(word) <= 15 { // Filter out empty lines and very long words
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading word list: %w", err)
	}

	if len(words) < 100 {
		return nil, fmt.Errorf("word list too small: got %d words", len(words))
	}

	return words, nil
}

func DefaultConfig() Config {
	return Config{
		Length:               12,
		IncludeUpper:         true,
		IncludeLower:         true,
		NumberCount:          1,
		SpecialChars:         "!@#$%^&*-_=+",
		NoConsecutive:        false,
		UsePassphrase:        true, // Default to passphrase
		WordCount:            3,
		NumberPosition:       "end",
		PassphraseUseNumbers: true,
		PassphraseUseSpecial: true,
	}
}

func GeneratePassword(config Config) (string, error) {
	if config.UsePassphrase {
		return generatePassphrase(config)
	}
	return generateRandomPassword(config)
}

func generateRandomPassword(config Config) (string, error) {
	if config.Length < 1 {
		return "", fmt.Errorf("password length must be at least 1")
	}

	var charset string
	var required []string

	// Build character set
	if config.IncludeLower {
		charset += "abcdefghijklmnopqrstuvwxyz"
		required = append(required, "abcdefghijklmnopqrstuvwxyz")
	}
	if config.IncludeUpper {
		charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		required = append(required, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	}
	if config.NumberCount > 0 {
		charset += "0123456789"
		required = append(required, "0123456789")
	}
	if len(config.SpecialChars) > 0 {
		charset += config.SpecialChars
		required = append(required, config.SpecialChars)
	}

	if len(charset) == 0 {
		return "", fmt.Errorf("no character types selected")
	}

	password := make([]byte, config.Length)

	// Ensure at least one character from each required set
	usedPositions := make(map[int]bool)

	// First, place required numbers
	numbersPlaced := 0
	for numbersPlaced < config.NumberCount && numbersPlaced < config.Length {
		pos, err := rand.Int(rand.Reader, big.NewInt(int64(config.Length)))
		if err != nil {
			return "", err
		}
		posInt := int(pos.Int64())

		if !usedPositions[posInt] {
			char, err := rand.Int(rand.Reader, big.NewInt(10))
			if err != nil {
				return "", err
			}
			password[posInt] = byte('0' + char.Int64())
			usedPositions[posInt] = true
			numbersPlaced++
		}
	}

	// Then place at least one from each other required character set
	for _, reqSet := range required {
		if reqSet == "0123456789" {
			continue // Already handled numbers
		}

		placed := false
		attempts := 0
		for !placed && attempts < config.Length*2 {
			pos, err := rand.Int(rand.Reader, big.NewInt(int64(config.Length)))
			if err != nil {
				return "", err
			}
			posInt := int(pos.Int64())

			if !usedPositions[posInt] {
				char, err := rand.Int(rand.Reader, big.NewInt(int64(len(reqSet))))
				if err != nil {
					return "", err
				}
				password[posInt] = reqSet[char.Int64()]
				usedPositions[posInt] = true
				placed = true
			}
			attempts++
		}
	}

	// Fill remaining positions
	for i := 0; i < config.Length; i++ {
		if !usedPositions[i] {
			char, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
			if err != nil {
				return "", err
			}
			password[i] = charset[char.Int64()]
		}
	}

	// Handle no consecutive characters requirement
	if config.NoConsecutive {
		return ensureNoConsecutive(string(password), charset)
	}

	return string(password), nil
}

func generatePassphrase(config Config) (string, error) {
	if config.WordCount < 1 {
		return "", fmt.Errorf("word count must be at least 1")
	}

	// Get current word list (online or fallback)
	currentWordList := getWordList()

	words := make([]string, config.WordCount)
	for i := 0; i < config.WordCount; i++ {
		wordIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(currentWordList))))
		if err != nil {
			return "", err
		}
		word := currentWordList[wordIndex.Int64()]

		// Capitalize first letter if upper case is enabled
		if config.IncludeUpper {
			word = strings.Title(word)
		}
		words[i] = word
	}

	// Generate numbers if enabled and needed
	var numbers []string
	if config.PassphraseUseNumbers && config.NumberCount > 0 {
		for i := 0; i < config.NumberCount; i++ {
			num, err := rand.Int(rand.Reader, big.NewInt(10))
			if err != nil {
				return "", err
			}
			numbers = append(numbers, fmt.Sprintf("%d", num.Int64()))
		}
	}

	// Helper function to get random separator
	getSeparator := func() string {
		if config.PassphraseUseSpecial && len(config.SpecialChars) > 0 {
			sepIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(config.SpecialChars))))
			if err != nil {
				return "" // fallback to no separator
			}
			return string(config.SpecialChars[sepIndex.Int64()])
		}
		return ""
	}

	// Default separator for non-random cases
	defaultSeparator := ""
	if config.PassphraseUseSpecial && len(config.SpecialChars) > 0 {
		defaultSeparator = "-"
	}

	// Combine based on number position
	var result string
	if len(numbers) == 0 {
		// No numbers, join words with separators only if special chars are enabled
		if config.PassphraseUseSpecial && len(config.SpecialChars) > 0 {
			var parts []string
			for i, word := range words {
				parts = append(parts, word)
				if i < len(words)-1 { // Don't add separator after last word
					parts = append(parts, getSeparator())
				}
			}
			result = strings.Join(parts, "")
		} else {
			// No special characters, just concatenate words without separators
			result = strings.Join(words, "")
		}
	} else {
		switch config.NumberPosition {
		case "start":
			numberStr := strings.Join(numbers, "")
			if config.PassphraseUseSpecial && len(config.SpecialChars) > 0 {
				var parts []string
				parts = append(parts, numberStr)
				for i, word := range words {
					parts = append(parts, getSeparator(), word)
					if i < len(words)-1 {
						parts = append(parts, getSeparator())
					}
				}
				result = strings.Join(parts, "")
			} else {
				result = numberStr + defaultSeparator + strings.Join(words, defaultSeparator)
			}
		case "end":
			numberStr := strings.Join(numbers, "")
			if config.PassphraseUseSpecial && len(config.SpecialChars) > 0 {
				var parts []string
				for i, word := range words {
					parts = append(parts, word)
					if i < len(words)-1 {
						parts = append(parts, getSeparator())
					}
				}
				parts = append(parts, getSeparator(), numberStr)
				result = strings.Join(parts, "")
			} else {
				result = strings.Join(words, defaultSeparator) + defaultSeparator + numberStr
			}
		case "each":
			var parts []string
			for i, word := range words {
				parts = append(parts, word)

				// Add the specified number of digits after each word
				for j := 0; j < config.NumberCount; j++ {
					num, err := rand.Int(rand.Reader, big.NewInt(10))
					if err != nil {
						return "", err
					}
					parts = append(parts, fmt.Sprintf("%d", num.Int64()))
				}

				// Add separator after each word+numbers (except last)
				if i < len(words)-1 {
					parts = append(parts, getSeparator())
				}
			}
			result = strings.Join(parts, "")
		default:
			numberStr := strings.Join(numbers, "")
			if config.PassphraseUseSpecial && len(config.SpecialChars) > 0 {
				var parts []string
				for i, word := range words {
					parts = append(parts, word)
					if i < len(words)-1 {
						parts = append(parts, getSeparator())
					}
				}
				parts = append(parts, getSeparator(), numberStr)
				result = strings.Join(parts, "")
			} else {
				result = strings.Join(words, defaultSeparator) + defaultSeparator + numberStr
			}
		}
	}

	return result, nil
}

func ensureNoConsecutive(password, charset string) (string, error) {
	passwordRunes := []rune(password)
	maxAttempts := 1000

	for attempt := 0; attempt < maxAttempts; attempt++ {
		hasConsecutive := false

		for i := 0; i < len(passwordRunes)-1; i++ {
			if passwordRunes[i] == passwordRunes[i+1] {
				// Replace the second character
				newChar, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
				if err != nil {
					return "", err
				}
				passwordRunes[i+1] = rune(charset[newChar.Int64()])
				hasConsecutive = true
			}
		}

		if !hasConsecutive {
			break
		}
	}

	return string(passwordRunes), nil
}
