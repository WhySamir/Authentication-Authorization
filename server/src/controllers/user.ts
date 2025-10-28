import { Request, Response } from "express";
import crypto from "crypto";

import { User } from "../models/user.model";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

import dotenv from "dotenv";
import { redis } from "../utils/redis";

dotenv.config();

const requiredEnvVars = [
  "REFRESH_TOKEN_SECRET",
  "ACCESS_TOKEN_SECRET",
  "EMAIL_USER",
  "EMAIL_PASS",
  "UPSTASH_REDIS_URL",
  "UPSTASH_REDIS_TOKEN",
];

requiredEnvVars.forEach((v) => {
  if (!process.env[v]) {
    throw new Error(`Missing required environment variable: ${v}`);
  }
});

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict" as "strict",
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
};

function hashToken(token: string) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
function setRefreshCookie(res: Response, refreshToken: string) {
  res.cookie("refreshToken", refreshToken, COOKIE_OPTIONS);
}
const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;

async function blacklistHash(hash: string, ttl = REFRESH_TOKEN_TTL_SECONDS) {
  if (!hash) return;
  await redis.set(`blacklist:${hash}`, "1", { ex: ttl });
}

export const signinUser = async (req: Request, res: Response) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !email || !password)
      return res.status(400).json({ message: "All fields are required" });

    if (username.length < 3 || password.length < 3 || email.length < 3) {
      return res
        .status(400)
        .json({ message: "username/password/email must be at least 3 chars" });
    }

    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
    });
    if (existingUser) {
      return res.status(300).json({ message: "User already exists" });
    }

    const user = await User.create({ username, email, password });
    if (!user) {
      return res.status(400).json({ message: "Failed to save in database" });
    }

    const refreshToken = user.generateRefreshToken();
    const accessToken = user.generateAccessToken();

    // store only the hash in DB
    const refreshTokenHash = hashToken(refreshToken);
    const refreshTokenExpires = new Date(
      Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000
    );

    user.refreshToken = refreshTokenHash;
    user.refreshTokenExpires = refreshTokenExpires;
    await user.save();

    //cookie to set refreshToken
    setRefreshCookie(res, refreshToken);

    return res.status(201).json({
      message: "User created successfully",
      user: { id: user._id, username: user.username, email: user.email },
      accessToken,
    });
  } catch (err) {
    console.error("signinUser error:", err);
    return res
      .status(500)
      .json({ message: "Server error or no data inserted", error: err });
  }
};

export const initiateLogin = async (req: Request, res: Response) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res
        .status(400)
        .json({ message: "Username/Email and password are required" });
    }

    // Find user by either username or email
    const user = await User.findOne({
      $or: [
        { email: identifier.toLowerCase() },
        { username: identifier.toLowerCase() },
      ],
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // If user signed up via Google (no password)
    if (!user.password) {
      return res.status(400).json({
        message: "This account uses Google Sign-In. Please log in with Google.",
      });
    }

    // Validate password
    const isPasswordValid = await user.isPasswordCorrect(password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    //Rate limiting key per user (based on email or user id)
    const rateLimitKey = `otp-requests:${user._id}`;

    // get current count
    const requestCount = await redis.get<number>(rateLimitKey);

    if (requestCount && requestCount >= 3) {
      return res.status(429).json({
        message: "You have reached the daily OTP request limit (3 per day).",
      });
    }

    if (requestCount) {
      await redis.incr(rateLimitKey);
    } else {
      // TTL = 24 hours (in seconds)
      await redis.set(rateLimitKey, 1, { ex: 24 * 60 * 60 });
    }

    // generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 2 * 60 * 1000); // expires in 2 min

    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER!,
        pass: process.env.EMAIL_PASS!,
      },
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER!,
      to: user.email,
      subject: "Your Login OTP",
      text: `Your OTP is ${otp}. It expires in 2 minutes.`,
    });

    return res.status(200).json({
      message: "OTP sent to your email",
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error", error: err });
  }
};

export const verifyLoginOtp = async (req: Request, res: Response) => {
  try {
    const { identifier, otp } = req.body;

    const user = await User.findOne({
      $or: [
        { email: identifier.toLowerCase() },
        { username: identifier.toLowerCase() },
      ],
    });

    if (!user) return res.status(404).json({ message: "User not found" });

    // check if otp is valid and not expired
    if (!user.otp || user.otp !== otp)
      return res.status(400).json({ message: "Invalid OTP" });

    if (user.otpExpires && user.otpExpires < new Date())
      return res.status(400).json({ message: "OTP expired" });

    // clear otp fields
    user.otp = undefined;
    user.otpExpires = undefined;

    // generate tokens
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    const refreshTokenHash = hashToken(refreshToken);
    user.refreshToken = refreshTokenHash;
    await user.save();

    // set refresh token cookie
    setRefreshCookie(res, refreshToken);

    return res.status(200).json({
      message: "Login successful",
      accessToken,
      user: { id: user._id, username: user.username, email: user.email },
    });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: err });
  }
};

export const logoutUser = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?._id;
    if (!userId) return res.status(401).json({ message: "Unauthorized" });

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    if (user.refreshToken) {
      await blacklistHash(user.refreshToken);
    }

    user.refreshToken = undefined;
    user.refreshTokenExpires = undefined;
    await user.save();

    res.clearCookie("refreshToken", COOKIE_OPTIONS);

    return res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    return res.status(500).json({ message: "Server error during logout" });
  }
};

export async function test(req: Request, res: Response) {
  return res.send("hello");
}
export const renewAccessToken = async (req: Request, res: Response) => {
  try {
    const token = req.cookies?.refreshToken;
    if (!token) return res.status(401).json({ message: "No token provided" });

    // 1) Verify JWT signature & expiry
    let decoded: any;
    try {
      decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET as string);
    } catch (err) {
      // invalid/expired JWT
      res.clearCookie("refreshToken");
      return res
        .status(403)
        .json({ message: "Invalid or expired token", error: err });
    }

    // 2) Token hash & blacklist check
    const tokenHash = hashToken(token);
    const isBlacklisted = await redis.get<string | null>(
      `blacklist:${tokenHash}`
    );
    if (isBlacklisted) {
      // token already blacklisted — possible reuse
      res.clearCookie("refreshToken");
      return res.status(403).json({ message: "Refresh token revoked" });
    }

    // 3) Load user and check stored hash + expiry
    const user = await User.findById(decoded._id);
    if (!user) {
      res.clearCookie("refreshToken");
      return res.status(404).json({ message: "User not found" });
    }

    // If user has no stored refresh token, force re-login
    if (!user.refreshToken || !user.refreshTokenExpires) {
      res.clearCookie("refreshToken");
      return res.status(401).json({ message: "Please login again" });
    }

    // 4) Absolute expiry check
    if (user.refreshTokenExpires.getTime() < Date.now()) {
      // Refresh period expired — invalidate DB and force login
      const storedHash = user.refreshToken;
      user.refreshToken = undefined;
      user.refreshTokenExpires = undefined;
      await user.save();
      // blacklist old stored hash (optional)
      if (storedHash) await blacklistHash(storedHash);
      res.clearCookie("refreshToken");
      return res.status(401).json({
        message: "Session expired — please login again",
        refreshExpired: true,
      });
    }

    // 5) Replay attack detection: incoming token hash must match stored hash
    if (user.refreshToken !== tokenHash) {
      // Mismatch -> either token stolen and replaced OR someone used it already.
      // Invalidate stored token and blacklist both the incoming token (replay) and stored token.
      const storedHash = user.refreshToken;
      user.refreshToken = undefined;
      user.refreshTokenExpires = undefined;
      await user.save();

      // Blacklist both the incoming token hash and the previous stored hash
      await blacklistHash(tokenHash);
      if (storedHash) await blacklistHash(storedHash);

      res.clearCookie("refreshToken");
      return res.status(403).json({
        message:
          "Refresh token mismatch detected — possible token theft. Please login again.",
      });
    }

    // 6) All checks passed -> ROTATE refresh token
    const newRefreshToken = user.generateRefreshToken(); // should return JWT string
    const newRefreshTokenHash = hashToken(newRefreshToken);
    const newExpiry = new Date(Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000);

    // store new hash and expiry atomically
    user.refreshToken = newRefreshTokenHash;
    user.refreshTokenExpires = newExpiry;
    await user.save();

    // blacklist the old token hash to prevent reuse
    await blacklistHash(tokenHash);

    // set cookie with new refresh token (httpOnly)
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: REFRESH_TOKEN_TTL_SECONDS * 1000,
    });

    // issue new access token
    const accessToken = user.generateAccessToken();

    return res.json({
      accessToken,
      tokenType: "Bearer",
      expiresIn: 15 * 60, // seconds
    });
  } catch (err) {
    console.error("renewAccessToken error:", err);
    res.clearCookie("refreshToken");
    return res.status(500).json({ message: "Server error", error: err });
  }
};
