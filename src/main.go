package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"regexp"
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

var (
	pathTraversalRegex = regexp.MustCompile(`(?:^|/)(?:\.\.(?:/|$))+`)
	dangerousPatterns = []*regexp.Regexp{
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
	ipBanMap = make(map[string]*ipBanInfo)
	ipBanMutex sync.RWMutex
)

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

	if info.requests > cfg.Security.IPBanList.MaxRequests {
		info.banned = true
		info.banUntil = now.Add(cfg.Security.IPBanList.BanDuration)
		return true
	}

	return false
}

func getMimeType(path string) string {
	ext := strings.TrimPrefix(filepath.Ext(path), ".")
	if mime, ok := cfg.MimeTypes[ext]; ok {
		if strings.HasPrefix(mime, "text/") || strings.Contains(mime, "javascript") || strings.Contains(mime, "json") || strings.Contains(mime, "xml") {
			return mime + "; charset=" + cfg.Charset
		}
		return mime
	}
	return "application/octet-stream"
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
	}

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

	file, err := os.Open(fullPath)
	if err != nil {
		logError(r, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", getMimeType(fullPath))
	setSecurityHeaders(w)
	size, err := io.Copy(w, file)
	if err != nil {
		logError(r, err)
		return
	}
	logAccess(r, http.StatusOK, size)
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Server", cfg.Headers.ServerName)
	w.Header().Set("X-Frame-Options", cfg.Headers.XFrameOptions)
	w.Header().Set("X-XSS-Protection", cfg.Headers.XSSProtection)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Content-Type", "text/html; charset="+cfg.Charset)
}

func main() {
	if err := os.MkdirAll(cfg.RootDir, 0755); err != nil {
		log.Fatal(err)
	}

	handler := http.HandlerFunc(handleRequest)

	for _, port := range cfg.Ports {
		go func(port string) {
			server := &http.Server{
				Addr:         port,
				Handler:      handler,
				ReadTimeout:  cfg.Timeout,
				WriteTimeout: cfg.Timeout,
			}

			if cfg.SSL.Enabled {
				server.TLSConfig = &tls.Config{
					MinVersion: tls.VersionTLS12,
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