package main

import (
	"net/http"
	"strings"
	"time"
)

var Version string

type Config struct {
	Version  string
	Ports    []string
	SSL      struct {
		Enabled  bool
		CertFile string
		KeyFile  string
	}
	RootDir  string
	MaxConns int
	Timeout  time.Duration

	Security struct {
		AllowBots    bool
		AllowPost    bool
		AllowPut     bool
		AllowDelete  bool
		AllowOptions bool
		AllowHead    bool
		AllowTrace   bool
		AllowConnect bool
		AllowPatch   bool
		IPBanList    struct {
			Enabled     bool
			MaxRequests int
			BanDuration time.Duration
		}
	}

	File struct {
		MaxFileSize   int64
		AllowHidden   bool
		AllowSymlinks bool
	}

	Directory struct {
		ShowDirSize bool
		ShowDirDate bool
		SortByName  bool
		SortByDate  bool
		SortBySize  bool
	}

	Headers struct {
		ServerName    string
		XFrameOptions string
		XSSProtection string
	}

	BlockedPaths      []string
	BlockedUserAgents []string
	AllowedUserAgents []string
	AllowedPaths      []string
	MimeTypes         map[string]string
}

const defaultHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Index of %s</title>
    <style>
        body { font-family: monospace; margin: 20px; }
        a { color: #0366d6; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .file { margin: 5px 0; }
        .dir { color: #0366d6; }
        .size { color: #666; }
        .date { color: #666; }
        .version { color: #666; font-size: 0.8em; }
    </style>
</head>
<body>
    <h1>Index of %s</h1>
    <hr>
    %s
    <hr>
    <em>alittleserver</em> <span class="version">%s</span>
</body>
</html>`

var cfg = Config{
	Version:  "dev",
	Ports:    []string{":8888",":8889", ":8890"},
	SSL: struct {
		Enabled  bool
		CertFile string
		KeyFile  string
	}{
		Enabled:  false,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	},
	RootDir:  "files",
	MaxConns: 1000,
	Timeout:  30 * time.Second,

	Security: struct {
		AllowBots    bool
		AllowPost    bool
		AllowPut     bool
		AllowDelete  bool
		AllowOptions bool
		AllowHead    bool
		AllowTrace   bool
		AllowConnect bool
		AllowPatch   bool
		IPBanList    struct {
			Enabled     bool
			MaxRequests int
			BanDuration time.Duration
		}
	}{
		AllowBots:    false,
		AllowPost:    false,
		AllowPut:     false,
		AllowDelete:  false,
		AllowOptions: false,
		AllowHead:    false,
		AllowTrace:   false,
		AllowConnect: false,
		AllowPatch:   false,
		IPBanList: struct {
			Enabled     bool
			MaxRequests int
			BanDuration time.Duration
		}{
			Enabled:     true,
			MaxRequests: 50,
			BanDuration: 24 * time.Hour,
		},
	},

	File: struct {
		MaxFileSize   int64
		AllowHidden   bool
		AllowSymlinks bool
	}{
		MaxFileSize:   100 * 1024 * 1024,
		AllowHidden:   false,
		AllowSymlinks: false,
	},

	Directory: struct {
		ShowDirSize bool
		ShowDirDate bool
		SortByName  bool
		SortByDate  bool
		SortBySize  bool
	}{
		ShowDirSize: false,
		ShowDirDate: false,
		SortByName:  true,
		SortByDate:  false,
		SortBySize:  false,
	},

	Headers: struct {
		ServerName    string
		XFrameOptions string
		XSSProtection string
	}{
		ServerName:    "alittleserver",
		XFrameOptions: "DENY",
		XSSProtection: "1; mode=block",
	},

	BlockedPaths: []string{
		"/phpmyadmin",
		"/wp-admin",
		"/admin",
		"/.git",
		"/.env",
		"/config",
		"/backup",
		"/db",
		"/sql",
		"/mysql",
		"/php",
		"/wp-",
		"/wordpress",
		"/administrator",
		"/joomla",
		"/drupal",
		"/.htaccess",
		"/.htpasswd",
		"/.well-known",
		"/cgi-bin",
		"/.svn",
		"/.idea",
		"/.vscode",
		"/node_modules",
		"/vendor",
		"/composer.json",
		"/package.json",
		"/yarn.lock",
		"/package-lock.json",
		"/composer.lock",
		"/Gemfile",
		"/Gemfile.lock",
		"/.DS_Store",
		"/Thumbs.db",
	},

	BlockedUserAgents: []string{
		"bot",
		"crawler",
		"spider",
		"bingbot",
		"googlebot",
		"yandexbot",
		"baiduspider",
		"facebookexternalhit",
		"twitterbot",
		"rogerbot",
		"linkedinbot",
		"embedly",
		"quora link preview",
		"showyoubot",
		"outbrain",
		"pinterest",
		"slackbot",
		"vkShare",
		"W3C_Validator",
		"redditbot",
		"Applebot",
		"WhatsApp",
		"flipboard",
		"tumblr",
		"bitlybot",
		"SkypeUriPreview",
		"nuzzel",
		"Discordbot",
		"Google Page Speed",
		"Qwantify",
		"archive.org_bot",
		"ia_archiver",
		"curl",
		"wget",
		"python-requests",
		"python-urllib",
		"java-http-client",
		"go-http-client",
		"ruby",
		"perl",
		"php",
		"node-fetch",
		"axios",
		"postman",
		"insomnia",
	},

	AllowedUserAgents: []string{
		"Googlebot",
		"Bingbot",
		"Yandexbot",
		"Baiduspider",
		"Slurp",
		"DuckDuckBot",
		"BingPreview",
		"Googlebot-Image",
		"Googlebot-News",
		"Googlebot-Video",
	},

	AllowedPaths: []string{
		"/robots.txt",
		"/sitemap.xml",
		"/favicon.ico",
		"/.well-known/security.txt",
	},

	MimeTypes: map[string]string{
		"html": "text/html; charset=utf-8",
		"css":  "text/css",
		"js":   "application/javascript",
		"json": "application/json",
		"png":  "image/png",
		"jpg":  "image/jpeg",
		"jpeg": "image/jpeg",
		"gif":  "image/gif",
		"svg":  "image/svg+xml",
		"txt":  "text/plain",
		"pdf":  "application/pdf",
		"xml":  "application/xml",
		"zip":  "application/zip",
		"doc":  "application/msword",
		"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"xls":  "application/vnd.ms-excel",
		"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"ppt":  "application/vnd.ms-powerpoint",
		"pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"mp3":  "audio/mpeg",
		"mp4":  "video/mp4",
		"webm": "video/webm",
		"webp": "image/webp",
		"ico":  "image/x-icon",
		"woff": "font/woff",
		"woff2": "font/woff2",
		"ttf":  "font/ttf",
		"eot":  "application/vnd.ms-fontobject",
		"otf":  "font/otf",
		"md":   "text/markdown",
		"yml":  "text/yaml",
		"yaml": "text/yaml",
		"toml": "text/toml",
		"ini":  "text/plain",
		"conf": "text/plain",
		"log":  "text/plain",
		"sh":   "text/plain",
		"bash": "text/plain",
		"zsh":  "text/plain",
		"fish": "text/plain",
		"go":   "text/plain",
		"rs":   "text/plain",
		"py":   "text/plain",
		"rb":   "text/plain",
		"php":  "text/plain",
		"java": "text/plain",
		"c":    "text/plain",
		"cpp":  "text/plain",
		"h":    "text/plain",
		"hpp":  "text/plain",
		"cs":   "text/plain",
		"swift": "text/plain",
		"kt":   "text/plain",
		"kts":  "text/plain",
		"ts":   "text/plain",
		"tsx":  "text/plain",
		"jsx":  "text/plain",
		"vue":  "text/plain",
		"svelte": "text/plain",
		"elm":  "text/plain",
		"clj":  "text/plain",
		"cljs": "text/plain",
		"ex":   "text/plain",
		"exs":  "text/plain",
		"erl":  "text/plain",
		"hrl":  "text/plain",
		"fs":   "text/plain",
		"fsx":  "text/plain",
		"fsi":  "text/plain",
		"fsproj": "text/plain",
		"vb":   "text/plain",
		"vbs":  "text/plain",
		"vbe":  "text/plain",
		"wsf":  "text/plain",
		"wsc":  "text/plain",
		"ws":   "text/plain",
		"wsh":  "text/plain",
		"ps1":  "text/plain",
		"psm1": "text/plain",
		"psd1": "text/plain",
		"ps1xml": "text/plain",
		"psc1": "text/plain",
		"pssc": "text/plain",
		"cdxml": "text/plain",
		"ps1config": "text/plain",
	},
}

func isBlocked(path string) bool {
	path = strings.ToLower(path)
	
	for _, allowed := range cfg.AllowedPaths {
		if path == allowed {
			return false
		}
	}
	
	for _, blocked := range cfg.BlockedPaths {
		if strings.Contains(path, blocked) {
			return true
		}
	}
	
	return false
}

func isBlockedUserAgent(ua string) bool {
	if cfg.Security.AllowBots {
		for _, allowed := range cfg.AllowedUserAgents {
			if strings.Contains(strings.ToLower(ua), strings.ToLower(allowed)) {
				return false
			}
		}
	}
	
	for _, blocked := range cfg.BlockedUserAgents {
		if strings.Contains(strings.ToLower(ua), strings.ToLower(blocked)) {
			return true
		}
	}
	
	return false
}

func isAllowedMethod(method string) bool {
	switch method {
	case http.MethodGet:
		return true
	case http.MethodPost:
		return cfg.Security.AllowPost
	case http.MethodPut:
		return cfg.Security.AllowPut
	case http.MethodDelete:
		return cfg.Security.AllowDelete
	case http.MethodOptions:
		return cfg.Security.AllowOptions
	case http.MethodHead:
		return cfg.Security.AllowHead
	case http.MethodTrace:
		return cfg.Security.AllowTrace
	case http.MethodConnect:
		return cfg.Security.AllowConnect
	case http.MethodPatch:
		return cfg.Security.AllowPatch
	default:
		return false
	}
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Server", cfg.Headers.ServerName)
	w.Header().Set("X-Frame-Options", cfg.Headers.XFrameOptions)
	w.Header().Set("X-XSS-Protection", cfg.Headers.XSSProtection)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
} 