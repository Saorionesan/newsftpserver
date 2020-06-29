# sftpserver

基于 https://github.com/ggrandes/sftpserver 进行的部分修改

## 一、安装与使用

### 1. 安装步骤

1. 在此处  [此处](http://47.103.2.6/SftpServer/) 可以下载到编译好的版本。

2. 将编译好的版本解压到对应的安装目录

3. 修改${InstallPath}/conf/2 中的配置文件，只需要修改application.properties ，修改其中数据库连接地址即可。

   

### 2. SftpServer 使用方法

启动前提条件：

1. 确保连接的数据库中存在 accounts 表。该表具有以下五个字段：username(用户名)、 pass(该用户密码)、homedirectory(用户家目录)、enableflag(是否启用该用户)、writepermission(用户是否具有写权限)。

2. 在使用FileZilla或者winscp连接SftpServer时，确保accounts表和SftpServer 中存在该用户家目录

   

启动、停止命令：

```shell
# 进入安装完成的bin目录中，使用sftpd.sh 脚本启动，请注意如果要成功启动当前服务器上需要存在Java环境
./sftpd.sh start # 启动

./sftpd.sh stop # 停止

```

使用方法：

1. 启动完毕后先在accounts表中创建用户，只需要添加用户名和密码即可，其余配置会自动生成
2. 向SftpServer发送post请求或者直接在安装目录下的home目录中，创建对应用户的家目录（目录名称要和数据库表中的用户名相同）
3. 使用FileZilla或者winscp，通过22222端口连接SftpServer，进行上传文件等操作。

## 二、配置SftpServer高可用

使用keepalived以及NFS 来完成SftpServer高可用的配置

### 1. 编译安装keepalived

需要在集群内每一台SftpServer服务器上安装配置`keepalived`。可以从此处[下载](http://47.103.2.6/SftpServer/keepalived/)获取到`keepalived`的安装部署包。具体的安装材料需求如下:

| 序号 | 文件名                                    | 作用             | 是否必须 |
| ---- | ----------------------------------------- | ---------------- | -------- |
| 1    | keepalived-1.2.16.tar.gz                  | keepalived源码   | 是       |
| 2    | gcc openssl openssl-devel popt popt-devel | keepalived依赖包 | 是       |
| 3    | 虚拟IP                                    | 配置集群的访问IP | 是       |

```shell
[root@localhost ~]# yum install gcc openssl  openssl-devel  popt popt-devel #编译与功能依赖包
[root@localhost ~]# tar -zxvf keepalived-1.2.16.tar.gz #解压安装部署包
[root@localhost keepalived-1.2.16]# cd keepalived-1.2.16
#编译安装keepalived
[root@localhost keepalived-1.2.16]# ./configure
[root@localhost keepalived-1.2.16]# make
[root@localhost keepalived-1.2.16]# make install
[root@localhost keepalived-1.2.16]# cp /usr/local/sbin/keepalived /usr/sbin/
[root@localhost keepalived-1.2.16]# cp /usr/local/etc/rc.d/init.d/keepalived /etc/init.d/
[root@localhost keepalived-1.2.16]# cp /usr/local/etc/sysconfig/keepalived /etc/sysconfig/
[root@localhost keepalived-1.2.16]# chmod +x /etc/init.d/keepalived
[root@localhost keepalived-1.2.16]# chkconfig keepalived on
[root@localhost keepalived-1.2.16]# mkdir /etc/keepalived
```

### 2 配置SftpServer高可用

#### 1. 配置keepalived

(1)主节点配置：

首先在Master 节点上配置keepalived：

```shell
[root@localhost ~]# vi /etc/keepalived/keepalived.conf #创建keepalived的配置文件
#####配置文件内容###########
! Configuration File for keepalived
global_defs {
   notification_email {
     #abc@example.com
   }
   #notification_email_from admin@example.com
   #smtp_server smtp.example.com
   #smtp_connect_timeout 30
   router_id sftp_master
}
vrrp_script chk_http_port {
    script "</dev/tcp/127.0.0.1/18121"    #监控本地SftpServer端口，根据实际配置
    interval 1
    weight -10
}
vrrp_instance VI_1 {
    state MASTER                    #主服务器
    interface eth0                #通信网卡，根据实际配置
    virtual_router_id 51  #路由标识，同网段内不可冲突且需与备用服务器一致
    priority 100                    #优先级，0-254
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass qwe123!@#
    }
    virtual_ipaddress {
        192.168.189.160            #虚拟IP，根据实际配置
    }
    track_script {
        chk_http_port
    }
}
[root@localhost ~]# service keepalived start #启动keepalived服务
```

(2)从节点配置：

编辑从节点的keepalived配置文件。

```
[root@localhost ~]# vi /etc/keepalived/keepalived.conf #创建keepalived的配置文件
#####配置文件内容###########
! Configuration File for keepalived
global_defs {
   notification_email {
     #abc@example.com
   }
   #notification_email_from admin@example.com
   #smtp_server smtp.example.com
   #smtp_connect_timeout 30
   router_id sftp_backup
}
vrrp_script chk_http_port {
    script "</dev/tcp/127.0.0.1/18121"    #监控本地SftpServer端口
    interval 1                        #执行间隔
    weight -10                    #执行失败，服务优先级-10
}
vrrp_instance VI_1 {
    state BACKUP                    #备用服务器
    interface eth0                    #通信网卡，根据实际配置
    virtual_router_id 51                #路由标识，需与主服务器一致，同网段内不可冲突
    priority 99                        #优先级，比主服务器要低，0-254
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass qwe123!@#
    }
    virtual_ipaddress {
        192.168.189.160            #虚拟IP，根据实际配置
    }
    track_script {
        chk_http_port
    }
}
[root@localhost ~]# service keepalived start #启动keepalived服务
```

分别在主从服务器上启动keepalived服务

#### 2. 主从节点挂载目录NFS配置

##### 2.1主节点端配置

##### 2.1.1安装系统依赖包

在从节点和主节点都需要安装,如果不安装的话将会报错。

```shell
[root@localhost ~]# yum install nfs-utils
```

##### 2.1.2主节点端配置NFS

(1)配置nfs

```shell
#编辑/etc/exports，指定共享目录及权限等
[root@localhost ~]# chmod 777 -R /var/DockerVolumes/data
 #如有windows客户端需连接该服务端，请设置文件夹权限，如客户端都是Linux，此步骤省略
[root@localhost ~]# vi /etc/exports  #编辑NFS共享文件夹权限与目录
#内容格式为：共享目录位置，允许共享机器的IP（权限信息）其中共享机器的IP也可以是一个IP地址段使用子网掩码指定
/var/DockerVolumes/data  192.168.189.159(rw,sync,anonuid=0,anongid=0)
```

（2）启动NFS服务

```shell
[root@localhost ~]# service rpcbind start
[root@localhost ~]# service nfs start
```

（3）设置NFS开机启动

```shell
####Centos7.0####
[root@localhost ~]# systemctl enable rpcbind.service #请注意启动先后顺序的问题，如果不按照顺序启动可能出现挂载不上去。
[root@localhost ~]# systemctl enable nfs-server.service
####Centos6.5####
[root@localhost ~]# chkconfig rpcbind on
[root@localhost ~]# chkconfig nfs on
```

##### 2.2 从节点配置

(1)检查从节点是否可以挂载

```shell
[root@localhost ~]# showmount -e 192.168.189.158  #服务器端ip
```

(2)从节点目录挂载

```shell
#将NFS主节点的目录挂载至本机/var/DockerVolumes/data目录上
[root@localhost ~]# mount -t nfs -o vers=4.0  192.168.189.158:/var/DockerVolumes/data /var/DockerVolumes/data
```

注意：配置完成后需要通过主节点的22222端口上传文件，除非主节点挂掉在通过从节点的22222端口上传文件。
