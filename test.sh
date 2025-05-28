#!/bin/bash

HOST=${1:-localhost}
PORT=${2:-8888}

echo "Testing dangerous user agents on $HOST:$PORT"

test_ua() {
    local ua=$1
    local expected=$2
    local response=$(curl -s -w "%{http_code}" -o /dev/null -H "User-Agent: $ua" "http://$HOST:$PORT/")
    
    if [ "$response" = "$expected" ]; then
        echo "✅ $ua: $response"
    else
        echo "❌ $ua: $response (expected $expected)"
    fi
}

echo -e "\nTesting blocked user agents (should return 000):"
test_ua "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "000"
test_ua "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)" "000"
test_ua "curl/7.64.1" "000"
test_ua "python-requests/2.28.1" "000"
test_ua "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)" "000"

echo -e "\nTesting normal user agents (should return 200):"
test_ua "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" "200"
test_ua "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" "200"
test_ua "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" "200" 
