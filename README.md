# nginx-http-flv-module

Media streming server based on nginx-rtmp-module.

# Features

* HTTP-based FLV streming (subscribe).

* GOP cache for low latency.

* 'Transfer-Encoding: chunked' response supported.

* Missing 'listen' directive in rtmp server block will be OK.

# Build

cd to NGINX source directory & run this:

    ./configure --add-module=/path/to/nginx-http-flv-module
    make
    make install

# Usage

* publish: ffmpeg -re -i example.mp4 -vcodec copy -acodec copy -f flv rtmp://example.com/myapp/mystream

* subscribe: http://localhost[:port]/live?[srv=0&app=myapp&]stream=mystream

# example nginx.conf

worker_processes  1;

error_log logs/error.log error;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;

    keepalive_timeout  65;

    server {
        listen       80;

        location / {
            root   /var/www;
            index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }

        location /live {
            flv_live on;
            chunked  on;
        }
    }
}

rtmp_auto_push on;
rtmp_auto_push_reconnect 1s;
rtmp_socket_dir /tmp;

rtmp {
    out_queue 4096;
    out_cork  8;

    server {
        listen 1935;

        application myapp {
            live on;
            gop_cache on;
            gop_cache_count 5;
        }
    }
}

