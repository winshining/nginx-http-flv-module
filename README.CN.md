# nginx-http-flv-module

基于[nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module)的流媒体服务器。

# 功能

* [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module)提供的所有功能。

* 基于HTTP协议的FLV直播流播放。

* GOP缓存，降低播放延迟 (H.264视频和AAC音频)。

* 支持'Transfer-Encoding: chunked'方式回复。

* rtmp配置的server块中可以省略'listen'配置项。

* 支持虚拟主机（试验）。

* 支持反向代理（试验）。

* 支持负载均衡（轮询，试验）。

# 支持的系统

* Linux（推荐）/FreeBSD/MacOS/Windows（受限）。

# 依赖

* 在类Unix系统上，需要GNU make，用于调用编译器来编译软件。

* 在类Unix系统上，需要GCC/在Windows上，需要MSVC，用于编译软件。

* 在类Unix系统上，需要GDB，用于调试软件（可选）。

* FFmpeg，用于发布媒体流。

* VLC播放器，用于播放媒体流。

* 如果NGINX要支持正则表达式，需要PCRE库。

* 如果NGINX要支持加密访问，需要OpenSSL库。

# 创建

下载[NGINX](http://nginx.org)和nginx-http-flv-module。

将它们解压到某一路径。

打开NGINX的源代码路径并执行：

    ./configure --add-module=/path/to/nginx-http-flv-module
    make
    make install

# 使用方法

关于[nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module)用法的详情，请参考[README.md](https://github.com/arut/nginx-rtmp-module/blob/master/README.md)。

    发布：ffmpeg -re -i example.mp4 -vcodec copy -acodec copy -f flv rtmp://example.com[:port]/appname/streamname

appname用于匹配rtmp配置块中的application块（更多详情见下文）。

streamname可以随意指定。

RTMP默认使用端口1935，如果要使用其他端口，必须指定':port'。

    播放: http://example.com[:port]/dir?[port=xxx&]app=myapp&stream=mystream

dir用于匹配http配置块中的location块（更多详情见下文）。

HTTP默认使用端口80, 如果使用了其他端口，必须指定':port'。

不再支持参数'srv=index'。

RTMP默认使用端口1935，如果使用了其他端口，必须指定'port=xxx'。

参数'app'用来匹配application块，但是如果请求的'app'出现在多个server块中，并且这些server块有相同的地址和端口配置，那么还需要用匹配主机名的'server_name'配置项来区分请求的是哪个application块，否则，将匹配第一个application块。

参数'stream'用来匹配发布流的streamname。

# nginx.conf实例

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
                flv_live on; #打开HTTP播放FLV直播流功能
                chunked  on; #支持'Transfer-Encoding: chunked'方式回复
            }

            location /stat {
                #push和pull状态的配置

                rtmp_stat all;
                rtmp_stat_stylesheet stat.xsl;
            }

            location /stat.xsl {
                root /var/www/rtmp; #指定stat.xsl的位置
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
            server_name www.test.*;

            application myapp {
                live on;
                gop_cache on; #打开GOP缓存，降低播放延迟
            }
        }

        server {
            listen 1935;
            server_name *.test.com;

            application myapp {
                live on;
                gop_cache on; #打开GOP缓存，降低播放延迟
            }
        }

        server {
            listen 1935;
            server_name www.test.com;

            application myapp {
                live on;
                gop_cache on; #打开GOP缓存，降低播放延迟
            }
        }

        server {
            listen 1945;

            application myapp {
                live on;
                gop_cache on; #打开GOP缓存，降低播放延迟
            }
        }

        server {
            listen 1985;

            application myapp {
                proxy_pass rtmp://balance; #打开反向代理
            }
        }

        upstream balance {
            #打开负载均衡

            server localhost:1935;
            server localhost:1945;
        }
    }

