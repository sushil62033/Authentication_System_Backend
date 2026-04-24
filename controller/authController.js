import User from "../src/services/models/userModel.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../src/config/config.js";
import sessionModel from "../src/services/models/SessionModel.js";

const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }
    if (!/\S+@\S+\.\S+/.test(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }
    if (password.length < 6) {
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters" });
    }
    if (await User.findOne({ email })) {
      return res.status(400).json({ error: "Email already exists" });
    }

    const hashedPassword = crypto
      .createHash("sha256")
      .update(password)
      .digest("hex");

    const user = await User.create({ name, email, password: hashedPassword });

    const refreshToken = jwt.sign({ userId: user._id }, config.JWT_SECRET, {
      expiresIn: "7d",
    });

    const refreshTokenHash = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    const session = await sessionModel.create({ userId: user._id, refreshTokenHash,ip:req.ip,userAgent:req.headers['user-agent'] });  

    const accessToken = jwt.sign({ userId: user._id }, config.JWT_SECRET, {
      expiresIn: "15m",
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(201).json({
      message: "User registered successfully",
      user: {
        name: user.name,
        email: user.email,
      },
      accessToken,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

const login = async(req,res)=>{
  try{
    const {email,password}=req.body;
    if(!email || !password){
      return res.status(400).json({
        message:"Email and password are required"
      })
    }
    const user = await User.findOne({email});
    if(!user){
      return res.status(401).json({
        message:"Invalid email or password"
      })
    }
    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");

    const isPasswordValid = hashedPassword === user.password;
    if(!isPasswordValid){
      return res.status(401).json({
        message:"Invalid email or password"
      })
    }
    const refreshToken=jwt.sign({
      userId:user._id,
    },config.JWT_SECRET,{
      expiresIn:"7d"
    })

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    const session = await sessionModel.create({
      userId:user._id,
      refreshTokenHash,
      ip:req.ip,
      userAgent:req.headers["user-agent"]
    })
    const accessToken = jwt.sign({
      userId:user._id,
      sessionId:session._id,
    },config.JWT_SECRET,{
      expiresIn:"15m"
    })
    res.cookie("refreshToken",refreshToken,{
      httpOnly:true,
      secure:true,  
      sameSite:"strict",
      maxAge:7*24*60*60*1000,
    });
    res.status(200).json({
      message:"Login successful",
      user:{    
        name:user.name,
        email:user.email,
      },
      accessToken,
    })  
  }catch(error){
    res.status(400).json({
      message:error.message
    })
  }
}

const getMe = async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const decoded = jwt.verify(token, config.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    res.status(200).json({
      message: "User found",
      user: {
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};
const refreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const newAccessToken = jwt.sign({ userId: user._id }, config.JWT_SECRET, {
      expiresIn: "15m",
    });
    const newRefreshToken = jwt.sign({ userId: user._id }, config.JWT_SECRET, {
      expiresIn: "7d",
    });
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      message: "Token refreshed successfully",
      accessToken: newAccessToken,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};
const logoutUser = async (req, res) => {

  try {
    const refreshToken = req.cookies.refreshToken;  
    if (!refreshToken) {
      return res.status(400).json({ error: "Refresh token is required" });
    }
    const refreshTokenHash = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");
    
   const session = await sessionModel.findOne(
      {refreshTokenHash, revoked: false },
    );
    if (!session) {
      return res.status(400).json({ error: "Invalid refresh token" });
    }
    session.revoked = true;
    await session.save();

    res.clearCookie("refreshToken");

    res.status(200).json({ message: "User logged out successfully" });
  } catch (error) {
    res.status(400).json({ error: error.message });

  }
};

const logoutAll= async(req,res)=>{
  try{
    const refreshToken=req.cookies.refreshToken;
    if(!refreshToken){
      return res.status(400).json({
        message:"Refresh Token not found"
      })
    }
    const decoded =jwt.verify(refreshToken,config.JWT_SECRET);
    await sessionModel.updateMany({
      userId:decoded.userId,
      revoked:false,

    },{
      revoked:true,
    })
    res.clearCookie("refreshToken");
    res.status(200).json({
      message:"Logout from all devices successfully"
    })
  }catch(error){
    res.status(400).json({
      message:error.message
    })
  }

}
export { registerUser,login, getMe, refreshToken, logoutUser, logoutAll };