import {Router} from "express";
import { registerUser, loginUser, logoutUser, logoutUserAll, refresh, getMe, updateUser } from "../controllers/user.controller.js";
import {verifyJWT} from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(registerUser);
router.route("/login").post(loginUser);

router.route("/logout").post(verifyJWT, logoutUser);
router.route("/logoutAll").post(verifyJWT, logoutUserAll);

router.route("/refresh").get(refresh);
router.route("/me")
  .get(verifyJWT, getMe)
  .patch(verifyJWT, updateUser);

export {router}