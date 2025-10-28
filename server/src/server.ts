import { connectToMongoDB } from "./config/db";
import dotenv from "dotenv";
import express, { Request, Response } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
dotenv.config();

const PORT = process.env.PORT;
const app = express();

connectToMongoDB();

const allowedOrigins = ["http://localhost:5173"];

//middlwares

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
  })
);
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(cookieParser());

//routes

import userRouter from "./routes/user.routes";

app.use("/api/v1/user", userRouter);

app.get("/", (req: Request, res: Response) => {
  res.send("Hello, TypeScript Backend with MongoDB!");
});

app.listen(PORT, () => {
  console.log("App running at Port no", PORT);
});
