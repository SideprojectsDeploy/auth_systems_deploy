import { connectDB } from "./db/index.js";
import { app } from "./app.js";
import dotenv from "dotenv";
import { ApiError } from "./utils/ApiError.js";
dotenv.config();

connectDB()
.then(() => {
  app.listen(process.env.PORT || 8000, () => {
    console.log(`Server is running at http://localhost:${process.env.PORT}`);
  });
})
.catch((err) => {
  throw new ApiError(404, "DB connection error ", err);
  console.log("DB connection error. ", err);
})