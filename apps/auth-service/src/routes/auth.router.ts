import express, { Router } from "express";
import { forgotPassword, loginUser, resetPassword, userRegistration, verifyUser, verifyUserForgetPassword } from "../controller/auth.controller";

const router:Router = express.Router();

router.post("/user-registation", userRegistration);
router.post("/verify-user", verifyUser);
router.post("/login-user", loginUser);
router.post("/forgot-password-user", forgotPassword);
router.post("/verify-forgot-password-user", verifyUserForgetPassword);
router.post("/reset-password-user", resetPassword);

export default router;