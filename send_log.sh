#!/bin/bash

# 이메일 설정
SUBJECT="Daily Resource Usage Log"
TO="1015hae@naver.com"
FROM="swuswu_pj2@example.com"
LOG_FILE="/var/log/resource_usage.log.1.gz"
BODY="Please find the attached log file for resource usage."

# 압축된 로그 파일을 이메일로 전송
echo "$BODY" | mail -s "$SUBJECT" -r "$FROM" -A "$LOG_FILE" "$TO"
