import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import { ApiError } from "./utils/ApiError.js";
import { ApiResponse } from "./utils/ApiResponse.js";
import dotenv from "dotenv";
dotenv.config();

const app = express();

app.use(express.json({limit: "16kb"}));
app.use(express.urlencoded({extended: true, limit: "16kb"}));
app.use(cors(
  {
    origin: process.env.CORS_ORIGIN,
    credentials: true
  }
));
app.use(cookieParser());
app.use(express.static("../public"));

// routes
import {router as userRouter} from "./routes/user.routes.js";

app.use("/api/v1/users", userRouter);


// if user requests on unavailable route
app.use("/", (req, res, next) => {
  next(new ApiError(404, "Route is not available."));
});

export {app}