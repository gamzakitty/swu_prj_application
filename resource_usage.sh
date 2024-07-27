#!/bin/bash

# 로그 파일 위치 설정( /var/log/파일명 이 기본 경로이나, 혹시 권한문제 발생시 우회)
LOG_FILE="/home/ubuntu/log_test/oldlog/resource_usage.log.1"

# 현재 시간 가져오기
CURRENT_TIME=$(date "+%Y-%m-%d %H:%M:%S")

# CPU 사용량 가져오기
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | \
           sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | \
           awk '{print 100 - $1"%"}')

# 메모리 사용량 가져오기
MEMORY_USAGE=$(free -m | awk 'NR==2{printf "Memory Usage: %s/%sMB (%.2f%%)\n", $3, $2, $3*100/$2 }')

# 디스크 사용량 가져오기
DISK_USAGE=$(df -h | awk '$NF=="/"{printf "Disk Usage: %d/%dGB (%s)\n", $3, $2, $5}')

# 로그 파일에 기록
echo "$CURRENT_TIME CPU Usage: $CPU_USAGE, $MEMORY_USAGE, $DISK_USAGE" >> $LOG_FILE
