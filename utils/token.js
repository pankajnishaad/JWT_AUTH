const jwt=require("jsonwebtoken");
const generateAccessToken=(userId)=>
{
    return jwt.sign({id: userId}, process.env.ACCESS_SECRET, {expiresIn: "1m",});
}

const generateRefreshToken=(userId)=>{
    return jwt.sign({id: userId},process.env.REFRESH_SECRET, {expiresIn: "7d",});
};
 module.exports={generateAccessToken, generateRefreshToken};
