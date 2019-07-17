package org.javastack.sftpserver.service;


import com.alibaba.druid.pool.DruidDataSource;
import org.javastack.sftpserver.entity.User;
import org.javastack.sftpserver.server.Server;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 *密码验证
 */
@Service
public class UserService  {

    @Autowired
    DruidDataSource druidDataSource;


    public User getUserByName(String username){
        User user=new User();
        try {
            Connection connection= druidDataSource.getConnection();
            String sql="select * from accounts where username=?";
            PreparedStatement preparedStatement=connection.prepareStatement(sql);
            preparedStatement.setString(1,username);
            ResultSet resultSet= preparedStatement.executeQuery();
            while (resultSet.next()){
                user.setUsername(resultSet.getString("username"));
                user.setPass(resultSet.getString("pass"));
                user.setEnableflag(resultSet.getString("enableflag"));
                user.setHomedirectory(resultSet.getString("homedirectory"));
                user.setWritepermission(resultSet.getString("writepermission"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return user;
    }

    public  Integer insertColumn(String username){
        String path= Server.homepath+"/"+username;
        int flag=0;
        try {
            Connection connection=druidDataSource.getConnection();
            String sql="UPDATE accounts set homedirectory=?,enableflag=?,writepermission=? where username=?";
            PreparedStatement preparedStatement=connection.prepareStatement(sql);
            preparedStatement.setString(1,path);
            preparedStatement.setString(2,"true");
            preparedStatement.setString(3,"true");
            preparedStatement.setString(4,username);
            flag=preparedStatement.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return flag;
    }

}
