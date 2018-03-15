# nginx-http-flv-module

[![Build Status](https://travis-ci.org/winshining/nginx-http-flv-module.svg?branch=master)](https://travis-ci.org/winshining/nginx-http-flv-module)

基于[nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module)的流媒体服务器。

# 功能

* [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module)提供的所有功能。

* 基于HTTP协议的FLV直播流播放。

* GOP缓存，降低播放延迟 (H.264视频和AAC音频)。

* 支持`Transfer-Encoding: chunked`方式的HTTP回复。

* rtmp配置的server块中可以省略`listen`配置项。

* 支持虚拟主机。

# 支持的系统

* Linux（推荐）/FreeBSD/MacOS/Windows（受限）。

# 依赖

* 在类Unix系统上，需要GNU make，用于调用编译器来编译软件。

* 在类Unix系统上，需要GCC/在Windows上，需要MSVC，用于编译软件。

* 在类Unix系统上，需要GDB，用于调试软件（可选）。

* FFmpeg，用于发布媒体流。

* VLC播放器（推荐），用于播放媒体流。

* 如果NGINX要支持正则表达式，需要PCRE库。

* 如果NGINX要支持加密访问，需要OpenSSL库。

# 创建

## 在Windows上

编译步骤请参考[Building nginx on the Win32 platform with Visual C](http://nginx.org/en/docs/howto_build_on_win32.html)。

## 在类Unix系统上

下载[NGINX](http://nginx.org)和nginx-http-flv-module。

将它们解压到某一路径。

打开NGINX的源代码路径并执行：

### 将模块编译进[NGINX](http://nginx.org)

    ./configure --add-module=/path/to/nginx-http-flv-module
    make
    make install

### 将模块编译为动态模块

    ./configure --add-dynamic-module=/path/to/nginx-http-flv-module
    make
    make install

### 注意

如果将模块编译为动态模块，那么[NGINX](http://nginx.org)的版本号**必须**大于或者等于1.9.11。

# 使用方法

关于[nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module)用法的详情，请参考[README.md](https://github.com/arut/nginx-rtmp-module/blob/master/README.md)。

## 发布

    ffmpeg -re -i example.mp4 -vcodec copy -acodec copy -f flv rtmp://example.com[:port]/appname/streamname

`appname`用于匹配rtmp配置块中的application块（更多详情见下文）。

`streamname`可以随意指定。

**RTMP默认端口**为**1935**，如果要使用其他端口，必须指定`:port`。

## 播放（HTTP）

    http://example.com[:port]/dir?[port=xxx&]app=myapp&stream=mystream

参数`dir`用于匹配http配置块中的location块（更多详情见下文）。

**HTTP默认端口**为**80**, 如果使用了其他端口，必须指定`:port`。

**RTMP默认端口**为**1935**，如果使用了其他端口，必须指定`port=xxx`。

参数`app`用来匹配application块，但是如果请求的`app`出现在多个server块中，并且这些server块有相同的地址和端口配置，那么还需要用匹配主机名的`server_name`配置项来区分请求的是哪个application块，否则，将匹配第一个application块。

参数`stream`用来匹配发布流的streamname。

## 例子

假设在`http`配置块中的`listen`配置项是：

    http {
        ...
        server {
            listen 8080; #不是默认的80端口
            ...

            location /live {
                flv_live on;
            }
        }
    }

在`rtmp`配置块中的`listen`配置项是：

    rtmp {
        ...
        server {
            listen 1985; #不是默认的1935端口
            ...

            application myapp {
                live on;
            }
        }
    }

那么HTTP播放的url是：

    http://example.com:8080/live?port=1985&app=myapp&stream=mystream

# 注意

由于一些播放器不支持HTTP块传输, 这种情况下最好**不要**在指定了`flv_live on;`的location中指定`chunked on;`，否则播放会失败。

# nginx.conf实例

## 注意

配置项`rtmp_auto_push`，`rtmp_auto_push_reconnect`和`rtmp_socket_dir`在Windows上不起作用，除了Windows 10 17063以及后续版本之外，因为多进程模式的`relay`需要Unix domain socket的支持，详情请参考[Unix domain socket on Windows 10](https://blogs.msdn.microsoft.com/commandline/2017/12/19/af_unix-comes-to-windows)。

    worker_processes  4; #运行在Windows上时，设置为1，因为Windows不支持Unix domain socket
    worker_cpu_affinity  0001 0010 0100 1000; #运行在Windows上时，省略此配置项

    error_log logs/error.log error;

    #如果此模块被编译为动态模块并且要使用与RTMP相关的功
    #能时，必须指定下面的配置项并且它必须位于events配置
    #项之前，否则NGINX启动时不会加载此模块或者加载失败
    #load_module modules/ngx_rtmp_module.so;

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
            server_name www.test.*; #用于虚拟主机名后缀通配

            application myapp {
                live on;
                gop_cache on; #打开GOP缓存，降低播放延迟
            }
        }

        server {
            listen 1935;
            server_name *.test.com; #用于虚拟主机名前缀通配

            application myapp {
                live on;
                gop_cache on; #打开GOP缓存，降低播放延迟
            }
        }

        server {
            listen 1935;
            server_name www.test.com; #用于虚拟主机名完全匹配

            application myapp {
                live on;
                gop_cache on; #打开GOP缓存，降低播放延迟
            }
        }
    }

