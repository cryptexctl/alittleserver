package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type fileInfo struct {
	name    string
	size    int64
	modTime time.Time
	isDir   bool
}

func getMimeType(path string) string {
	ext := strings.TrimPrefix(filepath.Ext(path), ".")
	if mime, ok := cfg.MimeTypes[ext]; ok {
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

func handleRequest(w http.ResponseWriter, r *http.Request) {
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

	fullPath := filepath.Join(cfg.RootDir, path)
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
			fileURL := filepath.Join(path, f.name)
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

		content := fmt.Sprintf(defaultHTML, path, path, strings.Join(fileList, ""), cfg.Version)

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

func main() {
	if err := os.MkdirAll(cfg.RootDir, 0755); err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:         cfg.Port,
		Handler:      http.HandlerFunc(handleRequest),
		ReadTimeout:  cfg.Timeout,
		WriteTimeout: cfg.Timeout,
	}

	fmt.Printf("Server starting on port %s\n", cfg.Port)
	log.Fatal(server.ListenAndServe())
} 