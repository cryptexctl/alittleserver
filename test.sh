#!/bin/bash

HOST=${1:-localhost}
PORT=${2:-8888}

echo "Testing dangerous user agents on $HOST:$PORT"

test_ua() {
    local ua=$1
    local expected=$2
    local response=$(curl -s -w "\n%{http_code}" -H "User-Agent: $ua" "http://$HOST:$PORT/")
    local status=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$status" = "$expected" ]; then
        echo "✅ $ua: $status"
        if [ "$status" = "000" ]; then
            echo "   Response: $body"
        fi
    else
        echo "❌ $ua: $status (expected $expected)"
        echo "   Response: $body"
    fi
}

test_path() {
    local path=$1
    local expected=$2
    local response=$(curl -s -w "\n%{http_code}" "http://$HOST:$PORT$path")
    local status=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$status" = "$expected" ]; then
        echo "✅ $path: $status"
        if [ "$status" = "000" ]; then
            echo "   Response: $body"
        fi
    else
        echo "❌ $path: $status (expected $expected)"
        echo "   Response: $body"
    fi
}

echo -e "\nTesting blocked user agents (should return 000):"
test_ua "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "000"
test_ua "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)" "000"
test_ua "curl/7.64.1" "000"
test_ua "python-requests/2.28.1" "000"
test_ua "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)" "000"
test_ua "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)" "000"
test_ua "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)" "000"
test_ua "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)" "000"
test_ua "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" "000"
test_ua "Mozilla/5.0 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)" "000"

echo -e "\nTesting normal user agents (should return 200):"
test_ua "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" "200"
test_ua "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" "200"
test_ua "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" "200"
test_ua "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1" "200"
test_ua "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1" "200"
test_ua "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15" "200"
test_ua "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0" "200"
test_ua "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0" "200"
test_ua "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0" "200"

echo -e "\nTesting path traversal (should return 000):"
test_path "/../../../../etc/passwd" "000"
test_path "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" "000"
test_path "/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd" "000"
test_path "/..%252f..%252f..%252f..%252fetc/passwd" "000"
test_path "/..%2f..%2f..%2f..%2fetc/passwd" "000"
test_path "/..%5c..%5c..%5c..%5cetc/passwd" "000"
test_path "/..%252f..%252f..%252f..%252fetc/passwd" "000"
test_path "/..%252e%252e%252f..%252e%252e%252f..%252e%252e%252f..%252e%252e%252fetc/passwd" "000" 
