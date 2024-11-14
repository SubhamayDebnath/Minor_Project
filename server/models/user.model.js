import { Schema, model } from "mongoose";

// Define the User schema
const userSchema = new Schema(
  {
    avatar: {
        public_id: { type: String },
        secure_url: { type: String },
    },
    username: {
      type: String,
      required: [true, "Username is required"],
      minLength: [3, "Username must be greater than 3 characters long"],
      maxLength: [26, "Username must be less than 26 characters long"],
      trim: true,
    },
    phone: {
      type: String,
      required: [true, "Phone number is required"],
      match: [/^\+?[1-9]\d{1,14}$/, "Please fill a valid phone number"],
      trim: true,
      unique: true,
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      lowercase: true,
      trim: true,
      unique: true,
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        "Please fill a valid email address",
      ],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minLength: [6, "Password must be greater than 6 characters long"],
      select: false, 
    },
    role: {
      type: String,
      enum: ["USER", "ADMIN", "SUPERUSER", "RESCUER"],
      default: "USER",
    },
    status: {
      type: String,
      enum: ["ACTIVE", "INACTIVE"],
      default: "ACTIVE",
    },
    isAuthenticated: {
      type: Boolean,
      default: false,
    },
    bloodGroup: {
        type: String,
        enum: ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-", "Unknown"],
        default: "Unknown",
    },
    allergies: {
        type: [String],
        default: [],
    },
    medicalProblems: {
        type: [String],
        default: [],
    },
    skills: {
        type: [String],
        enum: [
            "First Aid",
            "Search and Rescue",
            "Firefighting",
            "Medical Assistance",
            "Communication",
            "Logistics Support",
            "Disaster Relief",
            "Evacuation Assistance",
            "Water Rescue",
            "Mental Health Support",
        ],
        default: [],
     },
    isAvailable: {
        type: Boolean,
        default: true, 
    },
    location: {
        type: {
          type: String, 
          enum: ["Point"], 
          required: true,
        },
        coordinates: {
          type: [Number], 
          required: true,
        },
      }
  },
  {
    timestamps: true, 
  }
);
userSchema.index({ location: "2dsphere" });

const User = model("User", userSchema);
export default User;
