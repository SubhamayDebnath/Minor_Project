import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { config } from "dotenv";
import fs from "fs/promises";
import crypto from "crypto";
config();
import User from "../../models/user.model.js";
const jwtSecret = process.env.JWT_SECRET;
const cookieOption = {
  maxAge: 24 * 60 * 60 * 1000,
  httpOnly: true,
  secure: true,
};

/*
    Register
*/
const register = async (req, res, next) => {
  try {
    const { username, phone, email, password, latitude, longitude } = req.body;
    if (!username || !phone || !email || !password || !latitude || !longitude) {
      req.flash("error_msg", "Please fill in all fields");
      return res.redirect("/register");
    }
    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      if (existingUser.email === email && existingUser.phone === phone) {
        req.flash("error_msg", "Email and Phone already in use");
        return res.redirect("/register");
      } else if (existingUser.email === email) {
        req.flash("error_msg", "Email already in use");
        return res.redirect("/register");
      }else if (existingUser.phone === phone) {
        req.flash("error_msg", "Phone already in use");
        return res.redirect("/register");
      }
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      username,
      phone,
      email,
      password: hashedPassword,
      location: {
        type: "Point",
        coordinates: [longitude, latitude],
      },
    });
    if (!newUser) {
      req.flash("error_msg", "Failed to create user");
      return res.redirect("/register");
    }
    await newUser.save();
    res.redirect("/login");
  } catch (error) {
    console.log(`Register error : ${error}`);
    res.redirect("/error");
  }
};

/*
  login
*/ 

const login=async (req,res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      req.flash("error_msg", "Please fill in all fields");
      return res.redirect("/login");
    }
    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      req.flash("error_msg", "Invalid email or password");
      return res.redirect("/login");
    }
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      req.flash("error_msg", "Invalid email or password");
      return res.redirect("/login");
    }
    if (!user.isAuthenticated) {
      req.flash("error_msg", "Please active your account");
      res.redirect("/login");
    } else {
      const token = jwt.sign({ userId: user._id }, jwtSecret);
      res.cookie("token", token, cookieOption);
      res.redirect("/dashboard");
    }
  } catch (error) {
    console.log(`Login error : ${error}`);
    res.redirect("/error");
  }
}

/*
logout
*/ 
const logout = async (req, res, next) => {
  try {
    if(req.cookies.token){
      res.clearCookie("token");
      return res.redirect("/login");
    }
  } catch (error) {
    console.log(`Logout error : ${error}`);
    res.redirect("/error");
  }
};

export { register,login ,logout};
