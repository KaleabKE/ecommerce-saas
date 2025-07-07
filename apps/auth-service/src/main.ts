import express from 'express';
import cors from  "cors";
import { errorMiddleware } from "../../../packages/error-handler/error-middleware";
import cookieParser from 'cookie-parser';

const port = process.env.PORT || 6001
const app = express();

app.use(cors({
  origin: ["http://localhost:3000"],
  allowedHeaders: ["authorization", "content-type"],
  credentials: true
}));

app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
    res.send({ 'message': 'Hello API'});
});

app.use(errorMiddleware);

const server = app.listen(port, () => {
    console.log(`[ ready ] Auth service is running at http://localhost:${port}/api`);
});

server.on("error", (err) => {
  console.log("Server Error: ", err);
})
