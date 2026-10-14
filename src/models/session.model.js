import mongoose, {Schema} from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { ApiError } from "../utils/ApiError.js";

const sessionSchema = new Schema(
  {
    user_id: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    refreshTokenHash: {
      type: String,
    },
    userAgent: {
      type: String
    },
    ip: {
      type: String
    }
  }, {timestamps: true}
);

sessionSchema.methods.generateAccessToken = async function(){
  const {user_id} = await this.populate("user_id", "-passwordHash");

  if(!user_id){
    throw new ApiError(404, "User does not exist.");
  }

  return jwt.sign(
    {
      session_id: this._id,
      _id: user_id._id,
      email: user_id.email,
      username: user_id.username
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY
    }
  )
}

sessionSchema.methods.generateRefreshToken = function(){
  const userId = this.user_id?._id ?? this.user_id;
  return jwt.sign(
    {
      session_id: this._id,
      _id: userId
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY
    }
  )
}

sessionSchema.methods.saveRefreshToken = async function(refreshToken){
  this.refreshTokenHash = await bcrypt.hash(refreshToken, 10);
  await this.save();
}

sessionSchema.methods.deleteSession = async function(){
  await this.deleteOne();
}

const Session = mongoose.model("Session", sessionSchema);

async function createSession({ userAgent, ip, user_id }){
  const session = new Session({
    user_id: user_id,
    userAgent: userAgent,
    ip: ip
  });

  await session.save();
  return session;
}

export {Session, createSession}