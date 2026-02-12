const express= require("express");
const router=express.Router();
 const{registerUser, loginUser, refreshToken}=require("../controller/authController");

 router.post("/register", registerUser);
 router.post("/login", loginUser);
 router.post("/refresh-token", refreshToken);
 module.exports=router;
