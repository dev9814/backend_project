import express from "express"; 
import cors from 'cors';
import cookieParser from "cookie-parser";

const app = express();

var corsOptions = {
    origin: process.env.CORS_ORIGIN,
    credential: true
}
app.use(cors(corsOptions))

app.use(express.json({limit: "20kb"}))
app.use(express.urlencoded({extended: true, limit: "16kb"}))
app.use(express.static("public"))
app.use(cookieParser())

// routes import
import userRouter from './routes/user.routes.js'

// routes declaration
app.use("/api/v1/users", userRouter)

export { app }