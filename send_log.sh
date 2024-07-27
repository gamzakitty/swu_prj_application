#!/bin/bash

# 이메일 설정
SUBJECT="Daily Resource Usage Log"
TO="1015hae@naver.com"
FROM="929kong@gmail.com"
LOG_FILE="/home/ubuntu/log_test/oldlog/resource_usage.log.2.gz"
BODY="Please find the attached log file for resource usage."

# 압축된 로그 파일을 이메일로 전송
echo "$BODY" | mail -s "$SUBJECT" -r "$FROM" -A "$LOG_FILE" "$TO"
