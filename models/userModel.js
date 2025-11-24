import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    //Authentication fields
    name: { type: String, required: true, trim: true },
    email: {
        type: String, required: true, unique: true, lowercase: true,
        trim: true
    },
    password: { type: String, required: true },
    resetPasswordToken: { type: String },
    resetPasswordExpire: { type: Date },
    workingEvents: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Event' }]
},
    {
        timestamps: true
    });

const userModel = mongoose.models.User || mongoose.model("User", userSchema);
export default userModel;
