import Redis from "ioredis";

/*
const redis = new Redis({
    host: process.env.REDIS_HOST || "localhost",
    port: Number(process.env.REDIS_PORT) || 6379,
    password: process.env.REDIS_PASSWORD
});

*/

const redis = new Redis(process.env.REDIS_HOST!);

 export default redis;