import { Request, Response, NextFunction } from "express";
import { checkOtpRestrictions, sendOtp, trackOtpRequests, validateRegistrationData, verifyOtp } from "../utils/auth.helper";
import prisma from "@packages/libs/prisma";
import { AuthError, ValidationError } from "@packages/error-handler";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { setCookie } from "../utils/cookies/setCookie";

// Register a new user
export const userRegistration = async (req: Request, res: Response, next: NextFunction) => {
    try {
        validateRegistrationData(req.body, "user");
        const {name, email} = req.body;
        const existingUser = await prisma.users.findUnique({where: {email}})
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

// Verify user with OTP
export const verifyUser = async (req:Request, res:Response, next:NextFunction) => {
    try {
        const {email, otp, password, name} = req.body;
        if(!email || !otp || !password || !name){
            return next(new ValidationError("All fields are required!"))
        }
         const existingUser = await prisma.users.findUnique({where: {email}});
        if (existingUser){
            return next(new ValidationError("User already exists with this email!"))
        };
        await verifyOtp(email, otp, next);
        const hashedPassword = await bcrypt.hash(password, 10);

        await prisma.users.create({
            data: {name, email, password: hashedPassword}
        })

        res.status(201).json({
            success: true,
            message: "User registerd sucessfully!"
        })
    } catch (error) {
        next(error);
    }
}

export const loginUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const {email, password} = req.body;
        if (!email || !password){
           return next (new ValidationError("Email and password are required!"));
        }
        const user = await prisma.users.findUnique({where: {email}});
        if (!user) {
            return next (new AuthError("User doesn't exist!"));
        }

        // Verify password
        const isMatch = await bcrypt.compare(password, user.password!);
        if (!isMatch){
            return next (new AuthError("Invaild email or password!"));
        }

        // Generate access and refresh token
        const accessToken = jwt.sign({id: user.id, role: "user"}, process.env.ACCESS_TOKEN_SECRET!, {expiresIn: "15m"});
        const refreshToken = jwt.sign({id: user.id, role: "user"}, process.env.REFRESH_TOKEN_SECRET!, {expiresIn: "7d"});

        // Store the access and refresh token in an httpOnly secure cookie
        setCookie(res, "access_token", accessToken);
        setCookie(res, "refresh_token", refreshToken);

        res.status(200).json({
            message: "Login sucessful!",
            user: { id: user.id, email: user.email, name: user.name}
        });

    } catch (error) {
        return next(error)
    }
}