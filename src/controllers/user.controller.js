import { User, createUser } from "../models/user.model.js";
import { Session, createSession } from "../models/session.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { ApiError } from "../utils/ApiError.js";
import bcrypt from "bcrypt";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";

const refreshTokenOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  maxAge: 10*24*60*60*1000
}

const registerUser = asyncHandler(async (req, res, next) => {

  const { username, email, password } = req.body;

  const userLogged = await User.findOne({
    $or: [{ username }, { email }]
  });

  if (userLogged) {
    return next(new ApiError(409, "User already exists"));
  }

  const user = await createUser({ username, email, password });
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
        email,
        _id: user._id
      }
    )
  );
});

const loginUser = asyncHandler(async (req, res, next) => {

  const { email, password } = req.body;
  const isUser = await User.findOne({ email });

  if (!isUser) {
    return next(new ApiError(401, "User not registered."));
  }
  if (!(await bcrypt.compare(password, isUser.passwordHash))) {
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
        email: isUser.email,
        _id: isUser._id
      }
    )
  );
})

const logoutUser = asyncHandler(async (req, res, next) => {

  const refreshToken = req.cookies?.refreshToken;
  if (!refreshToken) {
    return next(new ApiError(401, "Refresh token not found."));
  }

  const decodedRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

  const session = await Session.findById(decodedRefreshToken.session_id);

  if (!session) {
    return next(new ApiError(401, "Session not found."));
  }

  const isValidRefreshToken = await bcrypt.compare(refreshToken, session.refreshTokenHash);
  if (!isValidRefreshToken) {
    return next(new ApiError(401, "Invalid refresh token."));
  }

  await session.deleteOne();

  res.clearCookie("refreshToken", refreshTokenOptions);

  return res.status(200).json(
    new ApiResponse(200, {}, "Logged out succesfully.")
  )
})

const logoutUserAll = asyncHandler(async (req, res, next) => {

  const refreshToken = req.cookies?.refreshToken;
  if (!refreshToken) {
    return next(new ApiError(401, "refresh token not found"));
  }

  const decodedRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
  const session = await Session.findById(decodedRefreshToken.session_id);

  if (!session) {
    return next(new ApiError(401, "session not found"));
  }

  const isValidRefreshToken = await bcrypt.compare(refreshToken, session.refreshTokenHash);
  if (!isValidRefreshToken) {
    return next(new ApiError(401, "Invalid refresh token"));
  }

  await Session.deleteMany({
    user_id: session.user_id
  });

  res.clearCookie("refreshToken", refreshTokenOptions);
  return res.status(200).json(
    new ApiResponse(200, {}, "Logged out from all devices succesfully.")
  )
})

const refresh = asyncHandler(async (req, res, next) => {

  const refreshToken = req.cookies?.refreshToken;
  if (!refreshToken) {
    return next(new ApiError(401, "Refresh token not found"));
  }

  const decodedRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

  const session = await Session.findById(decodedRefreshToken.session_id);
  if (!session) {
    return next(new ApiError(401, "Session not found"));
  }

  const isValidSession = await bcrypt.compare(refreshToken, session.refreshTokenHash);

  if (!isValidSession) {
    return next(new ApiError(401, "Invalid session"));
  }

  const { user_id } = await session.populate("user_id", "-passwordHash");
  const accessToken = await session.generateAccessToken();

  const newRefreshToken = await session.generateRefreshToken();
  await session.saveRefreshToken(newRefreshToken);

  res.cookie("refreshToken", newRefreshToken, refreshTokenOptions);
  res.status(200).json(
    new ApiResponse(200,
      {
        accessToken,
        username: user_id.username,
        email: user_id.email,
        _id: user_id._id,
      }
    )
  );
})

const getMe = asyncHandler(async (req, res) => {
  return res.status(200).json(
    new ApiResponse(200, req.user, "User fetched successfully")
  );
});

const updateUser = asyncHandler(async (req, res) => {

  const { newUsername, newEmail, newPassword } = req.body;
  const fields = [newUsername, newEmail, newPassword];

  if (!fields.every(field => field && field.trim())) {
    throw new ApiError(400, "All fields are required");
  }

  const updatedUser = await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        username: newUsername,
        email: newEmail,
        passwordHash: await bcrypt.hash(newPassword, 10)
      }
    },
    {
      new: true,
      runValidators: true
    }
  ).select("-passwordHash");

  return res.status(200).json(
    new ApiResponse(200, { user: updatedUser }, "User updated succesfully.")
  )
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