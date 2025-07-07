export class AppError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;
    public readonly details?: any;

    constructor (message:string, statusCode: number, isOperational = true, details?:any){
        super(message);
        this.statusCode = statusCode;
        this.isOperational = isOperational;
        this.details = details;
        Error.captureStackTrace(this);
    }
}

export class NotFoundError extends AppError {
    constructor(message: string = "Resource not found", details?: any) {
        super(message, 404, true, details);
    }
}

export class ValidationError extends AppError {
    constructor(message: string = "Invaild requst data", details?: any) {
        super(message, 400, true, details);
    }
}

export class AuthError extends AppError {
    constructor(message: string = "Authentication failed", details?: any) {
        super(message, 401, true, details);
    }
}

export class ForbiddenError extends AppError {
    constructor(message: string = "Access Forbidden", details?: any) {
        super(message, 403, true, details);
    }
}

export class DatabaseError extends AppError {
    constructor(message: string = "Database error", details?: any) {
        super(message, 500, true, details);
    }
}

export class RateLimitError extends AppError {
    constructor(message: string = "Too may requests, please try again later", details?: any) {
        super(message, 429, true, details);
    }
}
