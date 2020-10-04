# & docker run -d -p 59638:80 -v C:\dev\HttpProxy\HttpProxy\config:C:\app\config:ro --name httpproxy httpproxy:latest
& docker run -d -p 59638:80 -v C:\dev\HttpProxy\HttpProxy\config:/app/config:ro --name httpproxy httpproxy:latest
start "http://127.0.0.1:59638/test1"
