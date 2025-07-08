import crypto from "crypto";
import { ValidationError } from "../../../../packages/error-handler";
import redis from "../../../../packages/libs/redis";
import { sendEmail } from "./sendMail";
import { NextFunction } from "express";

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const validateRegistrationData = (data: any, userType: "user" | "seller") => {
    const {name, email, password, phone_number, country} = data;

    if (!name || !email || !password || (userType === "seller" && (!phone_number || !country)))
    {
        throw new ValidationError("Missing required fields!");
    }

    if (!emailRegex.test(email)) {
        throw new ValidationError("Invalid email format!");
    }
} 

export const checkOtpRestrictions = async (email: string, next:  NextFunction) => {
    if (await redis.get(`otp_lock:${email}`)){
        return next (new ValidationError("Account locked due to multiple failed attempts! Try again after 30 minutes."));
    }
    if(await redis.get(`otp_spam_lock:${email}`)){
        return next (new ValidationError("Too many requests! Please wait for an hour before trying again."));
    }
    if(await redis.get(`otp_cooldown:${email}`)){
        return next (new ValidationError("Please wait for 1 minutes before requesting for OTP!"));
    }
}

export const trackOtpRequests = async (email:string, next: NextFunction) => {
    const otpRequestKey = `otp_request_count:${email}`;
    let otpRequests = parseInt((await redis.get(otpRequestKey)) || "0");
    if (otpRequests >= 2){
        await redis.set(`otp_spam_lock:${email}`, "locked", "EX", 60 * 60);
        return next(new ValidationError("Too many OTP requests! Please wait for an hour before trying again."));
    }
    await redis.set(otpRequestKey, otpRequests + 1, "EX", 60 * 60);
}

export const sendOtp = async (name:string, email: string, template: string) => {
    const otp = crypto.randomInt(100000, 999999).toString();
    await sendEmail(email, "verify your Email", template, {name, otp} );
    await redis.set(`otp:${email}`, otp, "EX", 60 * 5);
    await redis.set(`otp_cooldown:${email}`, "true", "EX", 60);
    return otp;
}