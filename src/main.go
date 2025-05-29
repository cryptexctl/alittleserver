package main

import (
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"rsc.io/quote"
)

type fileInfo struct {
	name    string
	size    int64
	modTime time.Time
	isDir   bool
}

type ipBanInfo struct {
	requests    int
	lastRequest time.Time
	banned      bool
	banUntil    time.Time
}

type abuseIPDBResponse struct {
	Data struct {
		AbuseConfidenceScore int `json:"abuseConfidenceScore"`
	} `json:"data"`
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

var (
	pathTraversalRegex = regexp.MustCompile(`(?:^|/)(?:\.\.(?:/|$))+`)
	dangerousPatterns  = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:\.\.|%2e%2e|%252e%252e)`),
		regexp.MustCompile(`(?i)(?:\.\.\/|%2e%2e%2f|%252e%252e%252f)`),
		regexp.MustCompile(`(?i)(?:\.\.\\|%2e%2e%5c|%252e%252e%255c)`),
		regexp.MustCompile(`(?i)(?:\.\.%00|%2e%2e%00|%252e%252e%00)`),
		regexp.MustCompile(`(?i)(?:\.\.%2f|%2e%2e%2f|%252e%252e%252f)`),
		regexp.MustCompile(`(?i)(?:\.\.%5c|%2e%2e%5c|%252e%252e%255c)`),
		regexp.MustCompile(`(?i)(?:\.\.%3f|%2e%2e%3f|%252e%252e%253f)`),
		regexp.MustCompile(`(?i)(?:\.\.%23|%2e%2e%23|%252e%252e%2523)`),
		regexp.MustCompile(`(?i)(?:\.\.%26|%2e%2e%26|%252e%252e%2526)`),
		regexp.MustCompile(`(?i)(?:\.\.%3d|%2e%2e%3d|%252e%252e%253d)`),
		regexp.MustCompile(`(?i)(?:\.\.%2b|%2e%2e%2b|%252e%252e%252b)`),
		regexp.MustCompile(`(?i)(?:\.\.%21|%2e%2e%21|%252e%252e%2521)`),
		regexp.MustCompile(`(?i)(?:\.\.%40|%2e%2e%40|%252e%252e%2540)`),
		regexp.MustCompile(`(?i)(?:\.\.%24|%2e%2e%24|%252e%252e%2524)`),
		regexp.MustCompile(`(?i)(?:\.\.%25|%2e%2e%25|%252e%252e%2525)`),
		regexp.MustCompile(`(?i)(?:\.\.%5e|%2e%2e%5e|%252e%252e%255e)`),
		regexp.MustCompile(`(?i)(?:\.\.%26|%2e%2e%26|%252e%252e%2526)`),
		regexp.MustCompile(`(?i)(?:\.\.%2a|%2e%2e%2a|%252e%252e%252a)`),
		regexp.MustCompile(`(?i)(?:\.\.%28|%2e%2e%28|%252e%252e%2528)`),
		regexp.MustCompile(`(?i)(?:\.\.%29|%2e%2e%29|%252e%252e%2529)`),
		regexp.MustCompile(`(?i)(?:\.\.%7b|%2e%2e%7b|%252e%252e%257b)`),
		regexp.MustCompile(`(?i)(?:\.\.%7d|%2e%2e%7d|%252e%252e%257d)`),
		regexp.MustCompile(`(?i)(?:\.\.%5b|%2e%2e%5b|%252e%252e%255b)`),
		regexp.MustCompile(`(?i)(?:\.\.%5d|%2e%2e%5d|%252e%252e%255d)`),
		regexp.MustCompile(`(?i)(?:\.\.%7c|%2e%2e%7c|%252e%252e%257c)`),
		regexp.MustCompile(`(?i)(?:\.\.%60|%2e%2e%60|%252e%252e%2560)`),
		regexp.MustCompile(`(?i)(?:\.\.%27|%2e%2e%27|%252e%252e%2527)`),
		regexp.MustCompile(`(?i)(?:\.\.%22|%2e%2e%22|%252e%252e%2522)`),
		regexp.MustCompile(`(?i)(?:\.\.%3b|%2e%2e%3b|%252e%252e%253b)`),
		regexp.MustCompile(`(?i)(?:\.\.%3a|%2e%2e%3a|%252e%252e%253a)`),
		regexp.MustCompile(`(?i)(?:\.\.%3c|%2e%2e%3c|%252e%252e%253c)`),
		regexp.MustCompile(`(?i)(?:\.\.%3e|%2e%2e%3e|%252e%252e%253e)`),
		regexp.MustCompile(`(?i)(?:\.\.%3f|%2e%2e%3f|%252e%252e%253f)`),
		regexp.MustCompile(`(?i)(?:\.\.%2f|%2e%2e%2f|%252e%252e%252f)`),
		regexp.MustCompile(`(?i)(?:\.\.%5c|%2e%2e%5c|%252e%252e%255c)`),
		regexp.MustCompile(`(?i)(?:\.\.%7e|%2e%2e%7e|%252e%252e%257e)`),
	}
	ipBanMap   = make(map[string]*ipBanInfo)
	ipBanMutex sync.RWMutex
	fileCache  = make(map[string][]byte)
	cacheMutex sync.RWMutex
)

const (
	maxMimeCheckSize = 512
	maxSymlinkDepth  = 10
)

func checkAbuseIPDB(ip string) bool {
	if !cfg.Security.IPBanList.AbuseIPDB.Enabled {
		return false
	}

	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s", ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	req.Header.Set("Key", cfg.Security.IPBanList.AbuseIPDB.APIKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var result abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}

	return result.Data.AbuseConfidenceScore >= cfg.Security.IPBanList.AbuseIPDB.Score
}

func getRandomQuote() string {
	if !cfg.Security.Quotes.Enabled {
		return ""
	}

	quotes := []func() string{
		quote.Go,
		quote.Glass,
		quote.Hello,
		quote.Opt,
	}

	return quotes[rand.Intn(len(quotes))]()
}

func checkIPBan(ip string) bool {
	if !cfg.Security.IPBanList.Enabled {
		return false
	}

	ipBanMutex.Lock()
	defer ipBanMutex.Unlock()

	now := time.Now()
	info, exists := ipBanMap[ip]

	if !exists {
		info = &ipBanInfo{
			requests:    0,
			lastRequest: now,
		}
		ipBanMap[ip] = info
	}

	if info.banned {
		if now.After(info.banUntil) {
			info.banned = false
			info.requests = 0
			return false
		}
		return true
	}

	if now.Sub(info.lastRequest) > time.Minute {
		info.requests = 0
	}

	info.requests++
	info.lastRequest = now

	if info.requests > cfg.Security.IPBanList.MaxRequests || checkAbuseIPDB(ip) {
		info.banned = true
		info.banUntil = now.Add(cfg.Security.IPBanList.BanDuration)
		return true
	}

	return false
}

func checkSymlinkLoop(path string) error {
	visited := make(map[string]bool)
	current := path
	depth := 0

	for depth < maxSymlinkDepth {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}

		if (info.Mode() & os.ModeSymlink) == 0 {
			return nil
		}

		if visited[current] {
			return fmt.Errorf("symlink loop detected")
		}
		visited[current] = true

		link, err := os.Readlink(current)
		if err != nil {
			return err
		}

		if !filepath.IsAbs(link) {
			link = filepath.Join(filepath.Dir(current), link)
		}
		current = link
		depth++
	}

	return fmt.Errorf("symlink depth exceeded")
}

func getMimeType(path string, content []byte) string {
	if len(content) > maxMimeCheckSize {
		content = content[:maxMimeCheckSize]
	}

	mtype := mimetype.Detect(content)
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))

	if mtype.Is("application/octet-stream") {
		if mimeType, ok := cfg.MimeTypes[ext]; ok {
			return mimeType
		}
	}

	if strings.HasPrefix(mtype.String(), "text/") || strings.Contains(mtype.String(), "javascript") || strings.Contains(mtype.String(), "json") || strings.Contains(mtype.String(), "xml") {
		return mtype.String() + "; charset=" + cfg.Charset
	}

	return mtype.String()
}

func closeConnection(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	conn.Close()
}

func logAccess(r *http.Request, status int, size int64) {
	now := time.Now().Format("02/Jan/2006:15:04:05 -0700")
	fmt.Printf("%s - %s [%s] \"%s %s %s\" %d %d \"%s\" \"%s\"\n",
		r.RemoteAddr,
		"-",
		now,
		r.Method,
		r.URL.Path,
		r.Proto,
		status,
		size,
		r.Referer(),
		r.UserAgent(),
	)
}

func logError(r *http.Request, err error) {
	now := time.Now().Format("02/Jan/2006:15:04:05 -0700")
	fmt.Printf("[%s] [error] %s - %s \"%s %s %s\" \"%s\" \"%s\": %v\n",
		now,
		r.RemoteAddr,
		"-",
		r.Method,
		r.URL.Path,
		r.Proto,
		r.Referer(),
		r.UserAgent(),
		err,
	)
}

func sanitizePath(path string) (string, error) {
	path = strings.ReplaceAll(path, "\x00", "")

	if pathTraversalRegex.MatchString(path) {
		return "", fmt.Errorf("path traversal attempt detected")
	}

	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(path) {
			return "", fmt.Errorf("dangerous path pattern detected")
		}
	}

	cleanPath := filepath.Clean(path)

	if strings.HasPrefix(cleanPath, "\\") || strings.HasPrefix(cleanPath, "/") {
		cleanPath = strings.TrimPrefix(cleanPath, "/")
	}

	if strings.Contains(cleanPath, "\\") {
		return "", fmt.Errorf("invalid path format")
	}

	return cleanPath, nil
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	if checkIPBan(r.RemoteAddr) {
		w.WriteHeader(http.StatusTeapot)
		return
	}

	if !isAllowedMethod(r.Method) {
		logAccess(r, 444, 0)
		closeConnection(w)
		return
	}

	if isBlockedUserAgent(r.UserAgent()) {
		logAccess(r, 444, 0)
		closeConnection(w)
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/") {
		logAccess(r, http.StatusBadRequest, 0)
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	if isBlocked(r.URL.Path) {
		logAccess(r, 444, 0)
		closeConnection(w)
		return
	}

	path, err := url.QueryUnescape(r.URL.Path)
	if err != nil {
		logAccess(r, http.StatusBadRequest, 0)
		http.Error(w, "Invalid path encoding", http.StatusBadRequest)
		return
	}

	sanitizedPath, err := sanitizePath(path)
	if err != nil {
		logAccess(r, http.StatusBadRequest, 0)
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	fullPath := filepath.Join(cfg.RootDir, sanitizedPath)

	absRoot, err := filepath.Abs(cfg.RootDir)
	if err != nil {
		logError(r, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		logError(r, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !strings.HasPrefix(absPath, absRoot) {
		logAccess(r, http.StatusForbidden, 0)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	if err := checkSymlinkLoop(fullPath); err != nil {
		logAccess(r, http.StatusForbidden, 0)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			logAccess(r, http.StatusNotFound, 0)
			http.Error(w, "Not found", http.StatusNotFound)
		} else {
			logError(r, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if info.IsDir() {
		entries, err := os.ReadDir(fullPath)
		if err != nil {
			logError(r, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		var files []fileInfo
		for _, entry := range entries {
			name := entry.Name()
			if !cfg.File.AllowHidden && strings.HasPrefix(name, ".") {
				continue
			}

			if entry.IsDir() {
				name = "/" + name
			}

			fi, err := entry.Info()
			if err != nil {
				continue
			}

			files = append(files, fileInfo{
				name:    name,
				size:    fi.Size(),
				modTime: fi.ModTime(),
				isDir:   entry.IsDir(),
			})
		}

		if cfg.Directory.SortByDate {
			sort.Slice(files, func(i, j int) bool {
				return files[i].modTime.After(files[j].modTime)
			})
		} else if cfg.Directory.SortBySize {
			sort.Slice(files, func(i, j int) bool {
				return files[i].size > files[j].size
			})
		} else if cfg.Directory.SortByName {
			sort.Slice(files, func(i, j int) bool {
				return files[i].name < files[j].name
			})
		}

		var fileList []string
		for _, f := range files {
			fileURL := filepath.Join(sanitizedPath, f.name)
			fileInfo := fmt.Sprintf("<div class=\"file\"><a href=\"%s\" class=\"%s\">%s</a>", fileURL, map[bool]string{true: "dir", false: "file"}[f.isDir], f.name)

			if cfg.Directory.ShowDirSize || cfg.Directory.ShowDirDate {
				fileInfo += " ("
				if cfg.Directory.ShowDirSize {
					if f.isDir {
						fileInfo += "<span class=\"size\">dir</span>"
					} else {
						fileInfo += fmt.Sprintf("<span class=\"size\">%d bytes</span>", f.size)
					}
				}
				if cfg.Directory.ShowDirSize && cfg.Directory.ShowDirDate {
					fileInfo += ", "
				}
				if cfg.Directory.ShowDirDate {
					fileInfo += fmt.Sprintf("<span class=\"date\">%s</span>", f.modTime.Format("2006-01-02 15:04:05"))
				}
				fileInfo += ")"
			}

			fileInfo += "</div>"
			fileList = append(fileList, fileInfo)
		}

		content := fmt.Sprintf(defaultHTML, sanitizedPath, sanitizedPath, strings.Join(fileList, ""), Version)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		setSecurityHeaders(w)
		w.Write([]byte(content))
		logAccess(r, http.StatusOK, int64(len(content)))
		return
	} else {
		if !cfg.File.AllowSymlinks && (info.Mode()&os.ModeSymlink) != 0 {
			logAccess(r, 444, 0)
			closeConnection(w)
			return
		}

		if info.Size() > cfg.File.MaxFileSize {
			logAccess(r, http.StatusRequestEntityTooLarge, 0)
			http.Error(w, "File too large", http.StatusRequestEntityTooLarge)
			return
		}

		cacheMutex.RLock()
		cached, ok := fileCache[fullPath]
		cacheMutex.RUnlock()

		if ok {
			mimeType := getMimeType(fullPath, cached)
			w.Header().Set("Content-Type", mimeType)
			setSecurityHeaders(w)
			w.Header().Set("Cache-Control", "public, max-age=31536000")
			w.Header().Set("ETag", fmt.Sprintf("\"%x\"", info.ModTime().UnixNano()))
			w.Write(cached)
			logAccess(r, http.StatusOK, int64(len(cached)))
			return
		}

		if info.Size() > maxMimeCheckSize {
			mtype, err := mimetype.DetectFile(fullPath)
			if err == nil {
				w.Header().Set("Content-Type", mtype.String())
			} else {
				w.Header().Set("Content-Type", getMimeType(fullPath, nil))
			}
		} else {
			file, err := os.Open(fullPath)
			if err != nil {
				logError(r, err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			defer file.Close()

			content, err := io.ReadAll(file)
			if err != nil {
				logError(r, err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			cacheMutex.Lock()
			fileCache[fullPath] = content
			cacheMutex.Unlock()

			w.Header().Set("Content-Type", getMimeType(fullPath, content))
		}

		setSecurityHeaders(w)
		w.Header().Set("Cache-Control", "public, max-age=31536000")
		w.Header().Set("ETag", fmt.Sprintf("\"%x\"", info.ModTime().UnixNano()))

		mimeType := w.Header().Get("Content-Type")
		shouldCompress := strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") &&
			(strings.HasPrefix(mimeType, "text/") ||
				strings.Contains(mimeType, "javascript") ||
				strings.Contains(mimeType, "json") ||
				strings.Contains(mimeType, "xml"))

		if shouldCompress {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			defer gz.Close()

			if ok {
				gz.Write(cached)
			} else {
				file, err := os.Open(fullPath)
				if err != nil {
					logError(r, err)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}
				defer file.Close()

				io.Copy(gz, file)
			}
		} else {
			if ok {
				w.Write(cached)
			} else {
				file, err := os.Open(fullPath)
				if err != nil {
					logError(r, err)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}
				defer file.Close()

				io.Copy(w, file)
			}
		}

		logAccess(r, http.StatusOK, info.Size())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	if err := os.MkdirAll(cfg.RootDir, 0755); err != nil {
		log.Fatal(err)
	}

	rand.Seed(time.Now().UnixNano())
	quote := getRandomQuote()
	if quote != "" {
		fmt.Printf("\n%s\n\n", quote)
	}

	handler := http.HandlerFunc(handleRequest)

	for _, port := range cfg.Ports {
		go func(port string) {
			server := &http.Server{
				Addr:         port,
				Handler:      handler,
				ReadTimeout:  cfg.Timeout,
				WriteTimeout: cfg.Timeout,
				IdleTimeout:  cfg.Timeout,
			}

			if cfg.SSL.Enabled {
				server.TLSConfig = &tls.Config{
					MinVersion:               tls.VersionTLS12,
					CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
					PreferServerCipherSuites: true,
				}
				fmt.Printf("Starting SSL server on port %s\n", port)
				log.Fatal(server.ListenAndServeTLS(cfg.SSL.CertFile, cfg.SSL.KeyFile))
			} else {
				fmt.Printf("Starting server on port %s\n", port)
				log.Fatal(server.ListenAndServe())
			}
		}(port)
	}

	select {}
}
