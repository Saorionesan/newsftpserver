package org.javastack.sftpserver;


import org.javastack.sftpserver.server.Server;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 启动器
 */

@SpringBootApplication
public class SftpServerMasterApplication {
    public static void main(String[] args) {
        SpringApplication.run(SftpServerMasterApplication.class,args);
        new Server().start();
    }
}
