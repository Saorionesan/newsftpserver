package org.javastack.sftpserver.entity;
/**
 * 用户实体类
 */
public class User {
    private String username;
    private String pass;
    private String homedirectory;
    private String enableflag;
    private String writepermission;
    public String getHomedirectory() {
        return homedirectory;
    }
    public void setHomedirectory(String homedirectory) {
        this.homedirectory = homedirectory;
    }
    public String getEnableflag() {
        return enableflag;
    }
    public void setEnableflag(String enableflag) {
        this.enableflag = enableflag;
    }
    public String getWritepermission() {
        return writepermission;
    }

    public void setWritepermission(String writepermission) {
        this.writepermission = writepermission;
    }

    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public String getPass() {
        return pass;
    }
    public void setPass(String pass) {
        this.pass = pass;
    }
}
