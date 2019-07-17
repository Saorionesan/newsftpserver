package org.javastack.sftpserver.config;

import com.alibaba.druid.pool.DruidDataSource;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class DruidConfig {

    @ConfigurationProperties(prefix = "spring.datasource")
    @Bean //将该对象添加到容器中
    public DruidDataSource druid(){
        //因为此类中所有属性和配置文件一一对应 所以可以直接绑定
        return  new DruidDataSource();
    }

}
