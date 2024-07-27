#!/bin/bash

# 이메일 설정
SUBJECT="Daily Resource Usage Log"
TO="1015hae@naver.com"
FROM="929kong@gmail.com"
LOG_FILE="/home/ubuntu/log_test/oldlog/resource_usage.log.2.gz"
BODY="Please find the attached log file for resource usage."

# 이메일 내용 및 첨부파일을 위한 임시 파일 생성
TMPFILE=$(mktemp /tmp/email.XXXXXX)
{
    echo "Subject: $SUBJECT"
    echo "To: $TO"
    echo "From: $FROM"
    echo "Content-Type: multipart/mixed; boundary=\"----=_Part_$(date +%s)\""
    echo ""
    echo "------=_Part_$(date +%s)"
    echo "Content-Type: text/plain"
    echo ""
    echo "$BODY"
    echo ""
    echo "------=_Part_$(date +%s)"
    echo "Content-Type: application/gzip"
    echo "Content-Disposition: attachment; filename=$(basename "$LOG_FILE")"
    echo ""
    cat "$LOG_FILE"
    echo ""
    echo "------=_Part_$(date +%s)--"
} > "$TMPFILE"

# 이메일 전송
msmtp --from="$FROM" -t < "$TMPFILE"

# 임시 파일 삭제
rm "$TMPFILE"
