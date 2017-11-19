# nginx-http-flv-module

Media streaming server based on [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module).

# Features

* HTTP-based FLV live streaming (subscribe).

* GOP cache for low latency (H.264 video and AAC audio).

* 'Transfer-Encoding: chunked' response supported.

* Missing 'listen' directive in rtmp server block will be OK.

* Reverse proxy supported (experimental).

* Load balance (round robin) supported (experimental).

# Systems supported

* Linux (recommended)/FreeBSD/MacOS/Windows (limited).

# Prerequisites

* GNU make for activating compiler on Unix-like systems to compile software.

* GCC for compiling on Unix-like systems/MSVC for compiling on Windows.

* GDB for debuging on Unix-like systems.

* FFmpeg for publishing media streams.

* VLC player for playing media streams.

* PCRE for NGINX if regular expressions needed.

* OpenSSL for NGINX if encrypted access needed.

# Build

Download [NGINX](http://nginx.org) and nginx-http-flv-module.

Uncompress them.

cd to NGINX source directory & run this:

    ./configure --add-module=/path/to/nginx-http-flv-module
    make
    make install

# Usage

    publish: ffmpeg -re -i example.mp4 -vcodec copy -acodec copy -f flv rtmp://example.com[:port]/appname/streamname

The appname is used to match an application block in rtmp block (see below for details).

The streamname can be specified at will.

The default port for RTMP is 1935, if some other ports were used, ':port' must be specified.

    subscribe: http://example.com[:port]/dir?[srv=0&app=myapp&]stream=mystream

The dir is used to match location blocks in http block (see below for details).

The default port for HTTP is 80, if some other ports were used, ':port' must be specified.

The default server block matched is the first one in rtmp block, if the requested server block is not the first one, 'srv=index (index start from 0)' must be specified.

The default application block matched is the first one in server block, if the requested application block is not the first one, 'app=xxx' must be specified.

# Example nginx.conf

    worker_processes  4;
    worker_cpu_affinity  0001 0010 0100 1000;

    error_log logs/error.log error;

    events {
        worker_connections  1024;
    }

    http {
        include       mime.types;
        default_type  application/octet-stream;

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
                flv_live on; #open flv live streaming (subscribe)
                chunked  on; #open 'Transfer-Encoding: chunked' response
            }
        }
    }

    rtmp_auto_push on;
    rtmp_auto_push_reconnect 1s;
    rtmp_socket_dir /tmp;

    rtmp {
        out_queue   4096;
        out_cork    8;
        max_streams 64;

        server {
            listen 1935;

            application myapp {
                live on;
                gop_cache on; #open GOP cache for low latency
            }
        }

        server {
            listen 1945;

            application myapp {
                live on;
                gop_cache on; #open GOP cache for low latency
            }
        }

        server {
            listen 1985;

            application myapp {
                proxy_pass rtmp://balance; #open reverse proxy
            }
        }

        upstream balance {
            #open load balance

            server localhost:1935;
            server localhost:1945;
        }
    }

