# nginx-http-flv-module

[![Build Status](https://travis-ci.org/winshining/nginx-http-flv-module.svg?branch=master)](https://travis-ci.org/winshining/nginx-http-flv-module)

基于 [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module) 的流媒体服务器。

[English README](https://github.com/winshining/nginx-http-flv-module/blob/master/README.md)。

如果您喜欢这个模块，可以通过赞赏来支持我的工作，非常感谢！

![reward_qrcode_winshining](https://raw.githubusercontent.com/wiki/winshining/nginx-http-flv-module/reward_qrcode_winshining.png)

### 感谢

* Igor Sysoev，[NGINX](http://nginx.org) 的作者。

* Roman Arutyunyan，[nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module) 的作者。

* 贡献者，详情见 [AUTHORS](https://github.com/winshining/nginx-http-flv-module/blob/master/AUTHORS)。

## 功能

* [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module) 提供的所有功能。

* nginx-http-flv-module 的其他功能与 [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module) 的对比：

|       功能        | nginx-http-flv-module | nginx-rtmp-module |                  备注                   |
| :---------------: | :-------------------: | :---------------: | :-------------------------------------: |
|  HTTP-FLV (播放)  |           √           |         x         |     支持 HTTPS-FLV 和 chunked 回复      | 
|      GOP 缓存     |           √           |         x         |                                         |
|      虚拟主机     |           √           |         x         |                                         |
| 省略 `listen` 配置|           √           |       见备注      |        配置中必须有一个 `listen`        |
|     纯音频支持    |           √           |       见备注      |`wait_video` 或 `wait_key` 开启后无法工作|
|  `reuseport` 支持 |           √           |         x         |                                         |
|  定时打印访问记录 |           √           |         x         |                                         |
|  JSON 风格的 stat |           √           |         x         |                                         |
|stat 中包含录制详情|           √           |         x         |                                         |

## 兼容性

[NGINX](http://nginx.org) 的版本**应该**大于或者等于 1.2.6，与其他版本的兼容性未知。

## 支持的系统

* Linux（推荐）/FreeBSD/MacOS/Windows（受限）。

## 支持的播放器

* [VLC](http://www.videolan.org) (RTMP & HTTP-FLV)/[OBS](https://obsproject.com) (RTMP & HTTP-FLV)/[JW Player](https://www.jwplayer.com) (RTMP)/[flv.js](https://github.com/Bilibili/flv.js) (HTTP-FLV).

### 注意

[flv.js](https://github.com/Bilibili/flv.js) 只能运行在支持 [Media Source Extensions](https://www.w3.org/TR/media-source) 的浏览器上。

## 依赖

* 在类 Unix 系统上，需要 GNU make，用于调用编译器来编译软件。

* 在类 Unix 系统上，需要 GCC。或者在 Windows 上，需要 MSVC，用于编译软件。

* 在类 Unix 系统上，需要 GDB，用于调试软件（可选）。

* [FFmpeg](http://ffmpeg.org) 或者 [OBS](https://obsproject.com)，用于发布媒体流。

* [VLC](http://www.videolan.org)（推荐）或者 [flv.js](https://github.com/Bilibili/flv.js)（推荐），用于播放媒体流。

* 如果 NGINX 要支持正则表达式，需要 [PCRE库](http://www.pcre.org)。

* 如果 NGINX 要支持加密访问，需要 [OpenSSL库](https://www.openssl.org)。

* 如果 NGINX 要支持压缩，需要 [zlib库](http://www.zlib.net)。

## 创建

### 注意

nginx-http-flv-module 包含了 [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module) 所有的功能，所以**不要**将 nginx-http-flv-module 和 [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module) 一起编译。

### 在 Windows 上

编译步骤请参考 [Building nginx on the Win32 platform with Visual C](http://nginx.org/en/docs/howto_build_on_win32.html)，不要忘了在 `Run configure script` 步骤中添加 `--add-module=/path/to/nginx-http-flv-module`。

#### 注意

如果使用没有完整支持 x64 的编译器来编译此模块，例如 VS2010，请务必使用默认设置（目标机器类型 x86）。

### 在类 Unix 系统上

下载 [NGINX](http://nginx.org) 和 nginx-http-flv-module。

将它们解压到某一路径。

打开 NGINX 的源代码路径并执行：

#### 将模块编译进 [NGINX](http://nginx.org)

    ./configure --add-module=/path/to/nginx-http-flv-module
    make
    make install

或者

#### 将模块编译为动态模块

    ./configure --add-dynamic-module=/path/to/nginx-http-flv-module
    make
    make install

#### 注意

如果将模块编译为动态模块，那么 [NGINX](http://nginx.org) 的版本号**必须**大于或者等于 1.9.11。

## 使用方法

关于 [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module) 用法的详情，请参考 [README.md](https://github.com/arut/nginx-rtmp-module/blob/master/README.md)。

### 发布

为了简单起见，不用转码：

    ffmpeg -re -i MEDIA_FILE_NAME -c copy -f flv rtmp://example.com[:port]/appname/streamname

#### 注意

一些旧版本的 [FFmpeg](http://ffmpeg.org) 不支持选项 `-c copy`，可以使用选项 `-vcodec copy -acodec copy` 替代。

`appname` 用于匹配 rtmp 配置块中的 application 块（更多详情见下文）。

`streamname` 可以随意指定，但是**不能**省略。

**RTMP 默认端口**为 **1935**，如果要使用其他端口，必须指定 `:port`。

### 播放

#### HTTP-FLV 方式

    http://example.com[:port]/dir?[port=xxx&]app=appname&stream=streamname

#### 注意

* 如果使用 [ffplay](http://www.ffmpeg.org/ffplay.html) 命令行方式播放流，那么**必须**为上述的 url 加上引号，否则 url 中的参数会被丢弃（有些不太智能的 shell 会把 "&" 解释为"后台运行"）。

* 如果使用 [flv.js](https://github.com/Bilibili/flv.js) 播放流，那么请保证发布的流被正确编码，因为 [flv.js](https://github.com/Bilibili/flv.js) **只支持 H.264 编码的视频和 AAC/MP3 编码的音频**。

参数 `dir` 用于匹配 http 配置块中的 location 块（更多详情见下文）。

**HTTP 默认端口**为 **80**, 如果使用了其他端口，必须指定 `:port`。

**RTMP 默认端口**为 **1935**，如果使用了其他端口，必须指定 `port=xxx`。

参数 `app` 的值（appname）用来匹配 application 块，但是如果请求的 `app` 出现在多个 server 块中，并且这些 server 块有相同的地址和端口配置，那么还需要用匹配主机名的 `server_name` 配置项来区分请求的是哪个 application 块，否则，将匹配第一个 application 块。

参数 `stream` 的值（streamname）用来匹配发布的流的名称。

#### 例子

假设在 `http` 配置块中的 `listen` 配置项是：

    http {
        ...
        server {
            listen 8080; #不是默认的 80 端口
            ...

            location /live {
                flv_live on;
            }
        }
    }

在 `rtmp` 配置块中的 `listen` 配置项是：

    rtmp {
        ...
        server {
            listen 1985; #不是默认的 1935 端口
            ...

            application myapp {
                live on;
            }
        }
    }

并且发布的流的名称是 `mystream`，那么基于 HTTP 的播放 url 是：

    http://example.com:8080/live?port=1985&app=myapp&stream=mystream

#### 注意

由于一些播放器不支持 HTTP 块传输, 这种情况下最好在指定了 `flv_live on;` 的 location 中指定 `chunked_transfer_encoding off`，否则播放会失败。

#### RTMP 方式

    rtmp://example.com[:port]/appname/streamname

#### HLS 方式

    http://example.com[:port]/dir/streamname.m3u8

#### DASH 方式

    http://example.com[:port]/dir/streamname.mpd

## 示例图片

### RTMP ([JW Player](https://www.jwplayer.com)) & HTTP-FLV ([VLC](http://www.videolan.org))

![RTMP & HTTP-FLV](samples/jwplayer_vlc.png)

### HTTP-FLV ([flv.js](https://github.com/Bilibili/flv.js))

![HTTP-FLV](samples/flv.js.png)

## nginx.conf 实例

### 注意

配置项 `rtmp_auto_push`，`rtmp_auto_push_reconnect` 和 `rtmp_socket_dir` 在 Windows 上不起作用，除了 Windows 10 17063 以及后续版本之外，因为多进程模式的 `relay` 需要 Unix domain socket 的支持，详情请参考 [Unix domain socket on Windows 10](https://blogs.msdn.microsoft.com/commandline/2017/12/19/af_unix-comes-to-windows)。

最好将配置项 `worker_processes` 设置为 1，因为在多进程模式下，`ngx_rtmp_stat_module` 可能不会从指定的 worker 进程获取统计数据，因为 HTTP 请求是被随机分配给 worker 进程的。`ngx_rtmp_control_module` 也有同样的问题。这个问题可以通过这个补丁 [per-worker-listener](https://github.com/arut/nginx-patches/blob/master/per-worker-listener) 优化。

另外，`vhost` 功能在单进程模式下没有问题，但是在多进程模式下还不能完全正确运行，等待修复。例如，下面的配置在多进程模式下是没有问题的：

    rtmp {
        ...
        server {
            listen 1935;
            server_name domain_name;

            application myapp {
                ...
            }
        }
    }

而使用下面的配置，当 publisher 在第二个 `server` 上发布媒体流，播放请求以该配置（不管端口是不是 1935）访问非 publisher 的 worker 进程时是有问题的：

    rtmp {
        ...
        server {
            listen 1935;
            server_name 1st_domain_name;

            application myapp {
                ...
            }
        }

        server {
            listen 1945;
            server_name 2nd_domain_name;

            application myapp {
                ...
            }
        }
    }

如果 [NGINX](http://nginx.org) 是以多进程模式运行并且平台支持 socket 选项 `SO_REUSEPORT`，那么在配置项 `listen` 后添加选项 `reuseport` 可以解决惊群问题。

    rtmp {
        ...

        server {
            listen 1935 reuseport;
            ...
        }
    }

### 配置实例

    worker_processes  1; #运行在 Windows 上时，设置为 1，因为 Windows 不支持 Unix domain socket
    #worker_processes  auto; #1.3.8 和 1.2.5 以及之后的版本

    #worker_cpu_affinity  0001 0010 0100 1000; #只能用于 FreeBSD 和 Linux
    #worker_cpu_affinity  auto; #1.9.10 以及之后的版本

    error_log logs/error.log error;

    #如果此模块被编译为动态模块并且要使用与 RTMP 相关的功
    #能时，必须指定下面的配置项并且它必须位于 events 配置
    #项之前，否则 NGINX 启动时不会加载此模块或者加载失败

    #load_module modules/ngx_http_flv_live_module.so;

    events {
        worker_connections  4096;
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
                flv_live on; #打开 HTTP 播放 FLV 直播流功能
                chunked_transfer_encoding on; #支持 'Transfer-Encoding: chunked' 方式回复

                add_header 'Access-Control-Allow-Origin' '*'; #添加额外的 HTTP 头
                add_header 'Access-Control-Allow-Credentials' 'true'; #添加额外的 HTTP 头
            }

            location /hls {
                types {
                    application/vnd.apple.mpegurl m3u8;
                    video/mp2t ts;
                }

                root /tmp;
                add_header 'Cache-Control' 'no-cache';
            }

            location /dash {
                root /tmp;
                add_header 'Cache-Control' 'no-cache';
            }

            location /stat {
                #推流播放和录制统计数据的配置

                rtmp_stat all;
                rtmp_stat_stylesheet stat.xsl;
            }

            location /stat.xsl {
                root /var/www/rtmp; #指定 stat.xsl 的位置
            }

            #如果需要 JSON 风格的 stat, 不用指定 stat.xsl
            #但是需要指定一个新的配置项 rtmp_stat_format

            #location /stat {
            #    rtmp_stat all;
            #    rtmp_stat_format json;
            #}

            location /control {
                rtmp_control all; #rtmp 控制模块的配置
            }
        }
    }

    rtmp_auto_push on;
    rtmp_auto_push_reconnect 1s;
    rtmp_socket_dir /tmp;

    rtmp {
        out_queue           4096;
        out_cork            8;
        max_streams         128;
        timeout             15s;
        drop_idle_publisher 15s;

        log_interval 5s; #log 模块在 access.log 中记录日志的间隔时间，对调试非常有用
        log_size     1m; #log 模块用来记录日志的缓冲区大小

        server {
            listen 1935;
            server_name www.test.*; #用于虚拟主机名后缀通配

            application myapp {
                live on;
                gop_cache on; #打开 GOP 缓存，减少首屏等待时间
            }

            application hls {
                live on;
                hls on;
                hls_path /tmp/hls;
            }

            application dash {
                live on;
                dash on;
                dash_path /tmp/dash;
            }
        }

        server {
            listen 1935;
            server_name *.test.com; #用于虚拟主机名前缀通配

            application myapp {
                live on;
                gop_cache on; #打开 GOP 缓存，减少首屏等待时间
            }
        }

        server {
            listen 1935;
            server_name www.test.com; #用于虚拟主机名完全匹配

            application myapp {
                live on;
                gop_cache on; #打开 GOP 缓存，减少首屏等待时间
            }
        }
    }
