import { User, createUser } from "../models/user.model.js";
import { Session, createSession } from "../models/session.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { ApiError } from "../utils/ApiError.js";
import bcrypt from "bcrypt";
import { asyncHandler } from "../utils/asyncHandler.js";

const refreshTokenOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  maxAge: Number(process.env.REFRESH_TOKEN_EXPIRY_MILISECONDS)
}

const registerUser = asyncHandler(async (req, res, next) => {

  const {username, email, password} = req.body;

  const userLogged = await User.findOne({
    $or: [{ username }, { email }]
  });
  
  if(userLogged){
    return next(new ApiError(409, "User already exists"));
  }

  const user = await createUser({username, email, password});
  const session = await createSession({
    userAgent: req.get("User-Agent"), ip: req.ip, user_id: user._id
  });

  const accessToken = await session.generateAccessToken();
  const refreshToken = await session.generateRefreshToken();
  await session.saveRefreshToken(refreshToken);

  res.cookie("refreshToken", refreshToken, refreshTokenOptions);
  res.status(200).json(
    new ApiResponse(200, 
      {
        accessToken,
        username,
        email
      }
    )
  );
});

const loginUser = asyncHandler(async (req, res, next) => {

  const {email, password} = req.body;
  const isUser = await User.findOne({email});

  if(!isUser){
    return next(new ApiError(401, "User not registered."));
  }
  if(!(await bcrypt.compare(password, isUser.passwordHash))){
    return next(new ApiError(401, "Password invalid"));
  }

  const session = await createSession(
    {
      userAgent: req.get("User-Agent"),
      ip: req.ip,
      user_id: isUser._id
    }
  );

  const accessToken = await session.generateAccessToken();
  const refreshToken = await session.generateRefreshToken();
  await session.saveRefreshToken(refreshToken);

  res.cookie("refreshToken", refreshToken, refreshTokenOptions);
  res.status(200).json(
    new ApiResponse(200, 
      {
        accessToken,
        username: isUser.username,
        email: isUser.email
      }
    )
  );
})

export {
  registerUser,
  loginUser,
  logoutUser,
  logoutUserAll,
  refresh,
  getMe,
  updateUser
}