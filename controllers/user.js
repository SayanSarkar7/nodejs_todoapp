import { User } from "../models/user.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { sendCookie } from "../utils/feature.js";

export const getAllUsers = async (req, res) => {
  try {
    res.json({
      success: true,
      message: "all",
    });
  } catch (error) {
    next(error);
  }
};

export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    let user = await User.findOne({ email });
    if (user) {
      return next(new ErrorHandler("user already exists", 400));
    }
    const encryptedPassword = await bcrypt.hash(password, 10);

    user = await User.create({ name, email, password: encryptedPassword });

    sendCookie(user, res, "registered successfully", 201);
  } catch (error) {
    next(error);
  }
};

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      return next(new ErrorHandler("invalid email or password", 400));
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return next(new ErrorHandler("invalid email or password", 400));
    }
    sendCookie(user, res, `Welcome back,${user.name}`, 200);
  } catch (error) {
    next(error);
  }
};

export const getMyProfile = (req, res) => {
  try {
    res.json({
      success: true,
      user: req.user,
    });
  } catch (error) {
    next(error);
  }
};
export const logout = (req, res) => {
  try {
    res
      .status(200)
      .cookie("token", "", {
        expires: new Date(Date.now()),
        sameSite: process.env.NODE_ENV==="Development" ? "lax" : "none",
        secure: process.env.NODE_ENV==="Development" ? false : true,
      })
      .json({
        success: true,
        user: req.user,
      });
  } catch (error) {
    next(error);
  }
};
