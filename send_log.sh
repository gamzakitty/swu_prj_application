#!/bin/bash

# 이메일 설정
SUBJECT="Daily Resource Usage Log"
TO="1015hae@naver.com"
FROM="929kong@gmail.com"
LOG_FILE="/home/ubuntu/log_test/oldlog/resource_usage.log.2.gz"
BODY="Please find the attached log file for resource usage."

# 이메일 내용 및 첨부파일을 위한 임시 파일 생성
TMPFILE=$(mktemp /tmp/email.XXXXXX)
echo "Subject: $SUBJECT" >> $TMPFILE
echo "To: $TO" >> $TMPFILE
echo "From: $FROM" >> $TMPFILE
echo "" >> $TMPFILE
echo "$BODY" >> $TMPFILE
uuencode "$LOG_FILE" $(basename "$LOG_FILE") >> $TMPFILE

# 이메일 전송
cat $TMPFILE | msmtp --read-envelope-from --auto-from "$TO"

# 임시 파일 삭제
rm $TMPFILE
