import {Response} from 'express';

export const setCookie = (res: Response, cookieName: string, cookieValue: string) => {
    res.cookie(cookieName, cookieValue, 
        {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            maxAge: 7 * 24 * 60 * 1000 // 7 day
        });
}