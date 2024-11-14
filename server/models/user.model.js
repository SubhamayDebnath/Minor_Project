import { Schema, model } from "mongoose";
const userSchema = new Schema(
  {
    username: {
      type: "String",
      required: [true, "Username is required"],
      minLength: [3, "Name must be greater than 3 character long"],
      maxLength: [26, "Name must be less than 26 character long"],
      trim: true,
    },
    email: {
      type: "String",
      required: [true, "Email is required"],
      lowercase: true,
      trim: true,
      unique: true,
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        "Please fill valid email address",
      ],
    },
    password: {
      type: "String",
      required: [true, "Password is required"],
      minLength: [6, "Password must be greater than 6 character long"],
      select: false,
    },
    avatar: {
      public_id: {
        type: String,
      },
      secure_url: {
        type: String,
      },
    },
    role: {
      type: "String",
      enum: ["USER", "ADMIN", "SUPERUSER"],
      default: "USER",
    },
    isActive: {
      type: "String",
      enum: ["ACTIVE", "INACTIVE"],
      default: "ACTIVE",
    },
    isAuthenticated:{
        type:Boolean,
        default:false
    },
    forgotPasswordToken: String,
    forgotPasswordExpiry: String,
  },
  {
    timestamps: true,
  }
);

const User = model("User", userSchema);
export default User;
