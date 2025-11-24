import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log("Database connected successfully");

    }
    catch (error) {
        console.error("Errror connecting to database:", error);
        process.exit(1);
    }
};
export default connectDB;