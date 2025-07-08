import express, { Router } from "express";
import { userRegistration } from "../controller/auth.controller";

const router:Router = express.Router();

router.post("/user-registation", userRegistration);

export default router;