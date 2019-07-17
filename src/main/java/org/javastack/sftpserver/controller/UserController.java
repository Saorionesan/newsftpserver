package org.javastack.sftpserver.controller;


import com.alibaba.fastjson.JSON;
import org.apache.tomcat.util.http.fileupload.FileUtils;
import org.javastack.sftpserver.entity.ResponseResult;
import org.javastack.sftpserver.server.Server;
import org.javastack.sftpserver.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("user")
public class UserController  {

    /**
     * 列出所有用户文件夹
     * @return
     */
    @RequestMapping("/list")
    public ResponseResult<String[]> list(){
     ResponseResult<String[]> rr=new ResponseResult<>();
        File file=new File(Server.homepath);
        String[] paths=file.list();
        rr.setData(paths);
        return  rr;
    }

    /**
     * 判断用户文件夹是否存在
     * @return
     * 接收数组参数
     */
    @RequestMapping(value = "/exists")
    public ResponseResult<List<String>> exists(@RequestBody String data){
        ResponseResult<List<String>> rr=new ResponseResult<>();
        /**
         * 使用fastjson必须将其转换成形如["test2","test12"]
         */
        List<String> datalist=getStringArray(data);
        List<String> exists=new ArrayList<>();
        for(int i=0;i<datalist.size();i++){
         //存在
         if (isexist(datalist.get(i))){
         exists.add(datalist.get(i));
          }
          }
        rr.setData(exists);
        return  rr;
    }
    /**
     * 创建用户文件夹
     * 判断其是否存在 如果存在即不创建 不存在创建
     * @return
     */
    @RequestMapping("/create")
    public ResponseResult<List<String>> create(@RequestBody String data){
        ResponseResult<List<String>> rr= new ResponseResult<>();
       List<String> datalist=getStringArray(data);
       List<String> creates=new ArrayList<>();
        for (String name:datalist) {
            if(!isexist(name)){
                creates.add(name);
                File file=new File(Server.homepath+"/"+name);
                file.mkdirs();
            }
        }
        rr.setData(creates);
        return  rr;
    }

    /**
     * 删除用户文件夹
     * 判断其是否存在 存在即删除
     * @return
     */
    @RequestMapping("/delete")
    public ResponseResult<List<String>> delete(@RequestBody String data){
       ResponseResult<List<String>> rr= new ResponseResult<>();
       List<String> delete= new ArrayList<>();
       List<String> dataList=getStringArray(data);
        for (String name:dataList) {
            if(isexist(name)){
                //存在即删除
                delete.add(name);
                try {
                    FileUtils.deleteDirectory(new File(Server.homepath+"/"+name));
                } catch (IOException e) {
                    e.printStackTrace();
                    rr.setCode(10503);
                    return rr;
                }
            }
        }
        rr.setData(delete);
        return rr;
    }

    @RequestMapping("/update")
    public ResponseResult<List<String>> update(@RequestBody String data){
        ResponseResult<List<String>> rr=new ResponseResult<>();
        List<String> datalist=getStringArray(data);
     if(datalist.size()%2==0){
         for(int i=0;i<datalist.size();i=i+2){
            File file=new File(Server.homepath+"/"+datalist.get(i));
            file.renameTo(new File(Server.homepath+"/"+datalist.get(i+1)));
         }
         rr.setData(datalist);
         return rr;
     }else{
         rr.setCode(10503);
         rr.setMessage("请输入正确的格式数据");
         return  rr;
     }
    }
    /**
     * 转换为str数组
     * @param data
     * @return
     */
    private  List<String> getStringArray(String data){
        String str=data.split(":")[1];
        List<String> datalist= JSON.parseArray(str.substring(0,str.length()-1),String.class);
        return  datalist;
    }
    /**
     * 判断该文件夹是否存在
     * @return
     */
    private boolean isexist(String string){
        File file=new File(Server.homepath);
        //当前目录下
        String[] paths=file.list();
        List<String> directorys=Arrays.asList(paths);
        return directorys.contains(string);
    }

    /**
     * 注意 spring中new对象会和注解冲突 使用new后该类中所有注解失效
     * @RequestMapping("test")
     *
     @RequestMapping("/test")
    public void getUserByName(String username){
        System.out.println(userService.insertColumn(username));
    }
     */

}
