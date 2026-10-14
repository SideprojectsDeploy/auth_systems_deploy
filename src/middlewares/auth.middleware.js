import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { Session } from "../models/session.model.js";

const verifyJWT = asyncHandler(async (req, res, next) => {
  // if user has accessToken
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if(!token){
    return next(new ApiError(401, "Access token not found."));
  }

  const decodedAccessToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

  const session = await Session.findById(decodedAccessToken.session_id);
  if (!session || session.user_id.toString() !== decodedAccessToken._id) {
    return next(new ApiError(401, "session not found."));
  }

  const user = await User.findById(decodedAccessToken?._id).select("-passwordHash");

  if (!user) {
    return next(new ApiError(401, "User not found."));
  }

  req.user = user;
  return next();
})