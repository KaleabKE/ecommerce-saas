import { Request, Response, NextFunction } from "express";
import { checkOtpRestrictions, sendOtp, trackOtpRequests, validateRegistrationData } from "../utils/auth.helper";
import prisma from "@packages/libs/prisma";
import { ValidationError } from "@packages/error-handler";


// Register a new user
export const userRegistration = async (req: Request, res: Response, next: NextFunction) => {
    try {
        validateRegistrationData(req.body, "user");
        const {name, email} = req.body;
        const existingUser = await prisma.users.findUnique({where: email})
        if (existingUser){
            return next(new ValidationError("User already exists with this email!"))
        };

        await checkOtpRestrictions(email, next);
        await trackOtpRequests(email, next);
        await sendOtp(name, email, "user-activation-mail");

        res.status(200).json({message: "OTP send to email. Please verify your accout."});
    } catch (error) {
        return next(error);
    }
}