import {Router} from "express";
import { registerUser, loginUser, logoutUser, logoutUserAll, refresh, getMe, updateUser } from "../controllers/user.controller.js";
import {verifyJWT} from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(registerUser);
router.route("/loginUser").post(loginUser);

router.route("/logoutUser").post(verifyJWT, logoutUser);
router.route("/logoutUserAll").post(verifyJWT, logoutUserAll);

router.route("/refresh").get(refresh);
router.route("/users/:id")
  .get(verifyJWT, getMe)
  .patch(verifyJWT, updateUser);

export {router}