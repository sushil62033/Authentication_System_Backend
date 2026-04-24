import mongoose from "mongoose";

const otpSchema = new mongoose.Schema({
    email:{
        type:String,
        required:[true,"Email is required"],
    },
    user:{
        type:mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: [true, "UserId is required"],
    },
    otpHash:{
        type: String,
        required:[true,"OTP hash is required"],
    },
    
},{timestamps:true});

export default mongoose.model("OTP",otpSchema);