import express, { Router } from "express";
import { userRegistration, verifyUser } from "../controller/auth.controller";

const router:Router = express.Router();

router.post("/user-registation", userRegistration);
router.post("/verify-user", verifyUser);

export default router;