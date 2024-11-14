import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { config } from "dotenv";
import fs from "fs/promises";
import crypto from "crypto";
config();
import User from "../../models/user.model.js";

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
      req.flash("error_msg", "Email already in use");
      return res.redirect("/register");
    }
    if (existingUser.email === email && existingUser.phone === phone) {
      req.flash("error_msg", "Email and Phone already in use");
      return res.redirect("/register");
    }
    if (existingUser.email === email) {
      req.flash("error_msg", "Email already in use");
      return res.redirect("/register");
    }
    if (existingUser.phone === phone) {
      req.flash("error_msg", "Phone already in use");
      return res.redirect("/register");
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      username,
      email,
      phone,
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

export { register };
