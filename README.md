# nginx-http-flv-module

[![Build Status](https://travis-ci.org/winshining/nginx-http-flv-module.svg?branch=master)](https://travis-ci.org/winshining/nginx-http-flv-module)

Media streaming server based on [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module).

# Features

* All features [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module) supplies.

* HTTP-based FLV live streaming (subscribe).

* GOP cache for low latency (H.264 video and AAC audio).

* `Transfer-Encoding: chunked` HTTP response supported.

* Missing `listen` directive in rtmp server block will be OK.

* Virtual hosts supported.

# Systems supported

* Linux (recommended)/FreeBSD/MacOS/Windows (limited).

# Prerequisites

* GNU make for activating compiler on Unix-like systems to compile software.

* GCC for compiling on Unix-like systems/MSVC for compiling on Windows.

* GDB for debuging on Unix-like systems.

* FFmpeg for publishing media streams.

* VLC player (recommended) for playing media streams.

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

For details about usages of [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module), please refer to [README.md](https://github.com/arut/nginx-rtmp-module/blob/master/README.md).

## Publish

    ffmpeg -re -i example.mp4 -vcodec copy -acodec copy -f flv rtmp://example.com[:port]/appname/streamname

The `appname` is used to match an application block in rtmp block (see below for details).

The `streamname` can be specified at will.

The **default port for RTMP** is **1935**, if some other ports were used, `:port` must be specified.

## Play (HTTP)

    http://example.com[:port]/dir?[port=xxx&]app=myapp&stream=mystream

The `dir` is used to match location blocks in http block (see below for details).

The **default port for HTTP** is **80**, if some other ports were used, `:port` must be specified.

The **default port for RTMP** is **1935**, if some other ports were used, `port=xxx` must be specified.

The `app` is used to match an application block, but if the requested `app` appears in several server blocks and those blocks have the same address and port configuration, host name matches `server_name` directive will be additionally used to identify the requested application block, otherwise the first one is matched.

The `stream` is used to match the publishing streamname.

## Example

Assuming that `listen` directive specified in `http` block is:

    http {
        ...
        server {
            listen 8080; #not default port 80
            ...

            location /live {
                flv_live on;
            }
        }
    }

And `listen` directive specified in `rtmp` block is:

    rtmp {
        ...
        server {
            listen 1985; #not default port 1935
            ...

            application myapp {
                live on;
            }
        }
    }

So the url of play using HTTP is:

    http://example.com:8080/live?port=1985&app=myapp&stream=mystream

# Note

Since some players don't support HTTP chunked transmission, it's better **NOT** to specify `chunked on;` in location where `flv_live on;` is specifed in this case, or play will fail.

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

            location /stat {
                #configuration of push & pull status

                rtmp_stat all;
                rtmp_stat_stylesheet stat.xsl;
            }

            location /stat.xsl {
                root /var/www/rtmp; #specify in where stat.xsl located
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
            server_name www.test.*; #for suffix wildcard matching of virtual host name

            application myapp {
                live on;
                gop_cache on; #open GOP cache for low latency
            }
        }

        server {
            listen 1935;
            server_name *.test.com; #for prefix wildcard matching of virtual host name

            application myapp {
                live on;
                gop_cache on; #open GOP cache for low latency
            }
        }

        server {
            listen 1935;
            server_name www.test.com; #for completely matching of virtual host name

            application myapp {
                live on;
                gop_cache on; #open GOP cache for low latency
            }
        }
    }

