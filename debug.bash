#debug bash

go run cmd/static-analyzer/main.go ../my-nginx/usr/sbin/nginx | grep �����| grep call

objdump -D ../my-nginx/usr/sbin/nginx | grep syscall

objdump -R ../my-nginx/usr/sbin/nginx | grep syscall
