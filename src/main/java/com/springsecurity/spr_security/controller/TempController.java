package com.springsecurity.spr_security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class TempController {

    @ResponseBody
    @RequestMapping(value = "/admin", method = RequestMethod.GET)
    public Object admin(){
        return "Welcome to Security project ADMIN";
    }

    @ResponseBody
    @RequestMapping(value = "/user", method = RequestMethod.GET)
    public Object user(){
        return "Welcome to Security project USER";
    }

    @ResponseBody
    @RequestMapping(value = "/manager", method = RequestMethod.GET)
    public Object manager(){
        return "Welcome to Security project MANAGER";
    }

}
