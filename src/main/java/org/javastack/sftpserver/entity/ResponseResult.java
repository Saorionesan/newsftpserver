package org.javastack.sftpserver.entity;

/**
 * 实体类
 * @param <T>
 */
public class ResponseResult<T> {
   private  Integer code=10200;
   private String message="";
   private T data;
    public Integer getCode() {
        return code;
    }
    public void setCode(Integer code) {
        this.code = code;
    }
    public String getMessage() {
        return message;
    }
    public void setMessage(String message) {
        this.message = message;
    }
    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }
}
