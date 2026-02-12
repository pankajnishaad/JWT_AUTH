const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const User=require("../model/User");
const {generateAccessToken, generateRefreshToken}=require("../utils/token");

//for registration
exports.registerUser=async (req, res)=>{
  const{ name, email, password}=req.body;
  const hashedPassword=await bcrypt.hash(password, 10);

  const user=await User.create({
    name,
    email,
    password: hashedPassword,
  });

  res.json({ message: "User Registered Successfully" });
};

//for login
exports.loginUser=async(req, res)=>{
  const{ email, password} = req.body;

  const user=await User.findOne({email});
  if(!user) return res.status(400).json({message:"User not found"});

  const isMatch=await bcrypt.compare(password, user.password);
  if(!isMatch)
    return res.status(400).json({message:"Invalid Credentials"});

  const accessToken=generateAccessToken(user._id);
  const refreshToken=generateRefreshToken(user._id);

  user.refreshToken = refreshToken;
  await user.save();

  res.json({accessToken, refreshToken});
};

// for refreshToken
exports.refreshToken=async(req, res)=>{
  const{refreshToken}=req.body;

  if(!refreshToken) return res.status(401).json({message:"Refresh token required"});

  const user=await User.findOne({refreshToken});

  if(!user) return res.status(403).json({message:"Invalid refresh token"});

  // Verification
  jwt.verify(refreshToken, process.env.REFRESH_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({message:"Token expired"});
    const newAccessToken=generateAccessToken(user._id);
    res.json({accessToken: newAccessToken });
  });
};