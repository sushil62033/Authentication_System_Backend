import mongoose from "mongoose";

const  userSchema = new mongoose.Schema({
    name:{
        type:String,
        required:[true,"UserName is required"],
        
    },
    email:{
        type:String,
        required:[true,"Email is required"],
        unique:[true,"Email must be unique"]

    },
    password:{
        type:String,
        required:[true,"Password is required"],
       
    },
    verified:{
        type:Boolean,
        default:false,
    },
})
const User = mongoose.model("User",userSchema);

export default User;