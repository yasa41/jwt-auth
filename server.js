import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";

//express 
import connectDB from "./config/mongodb.js";
import authRouter from "./routes/authRoutes.js";


dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

connectDB();

// Middlewares
app.use(cors({
  origin: "http://localhost:5173",
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

// Routes
app.use("/api/auth", authRouter);



app.get("/", (req, res) => {
  res.send("API is running...");
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Something went wrong!'
  });
});

app.listen(port, () =>
  console.log(`Server running at http://localhost:${port}`)
);
