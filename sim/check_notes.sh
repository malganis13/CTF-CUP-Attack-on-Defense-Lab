#!/bin/sh
echo "--- notes search quote ---"
curl -s -i --max-time 4 'http://127.0.0.1:8081/api/search?q=%27' | head -12
echo
echo "--- notes search normal ---"
curl -s --max-time 4 'http://127.0.0.1:8081/api/search?q=rel' | head -3
echo
echo "--- notes health ---"
curl -s --max-time 4 http://127.0.0.1:8081/health; echo
