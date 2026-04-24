import { Router } from "express";
import * as authController from "../controller/authController.js";

const authRouter = Router();

authRouter.post("/register", authController.registerUser);
authRouter.post("/login",authController.login);

authRouter.get("/get-me", authController.getMe);
authRouter.get("/refresh-token", authController.refreshToken);
authRouter.get("/logout", authController.logoutUser);
authRouter.get("/logout-all",authController.logoutAll);
authRouter.get("/verify-email",authController.verifyEmail);
export default authRouter;