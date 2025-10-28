import mongoose, { Document, Schema } from "mongoose";
import jwt, { Secret } from "jsonwebtoken";
import bcrypt from "bcrypt";

//Document for json like object presented in mongodbs

export interface IUser extends Document {
  username: string;
  email: string;
  password?: string; // optional because Google users may not have it
  refreshToken?: string;
  refreshTokenExpires?: Date;
  googleId?: string;
  isPasswordCorrect(password: string): Promise<boolean>; //promise cause of bcrypt.compare async
  generateAccessToken(): string; //sync no callbacks
  generateRefreshToken(): string;
  otp?: string;
  otpExpires?: Date;
}

const userSchema = new Schema<IUser>(
  {
    username: {
      type: String,
      required: true,
      lowercase: true,
      unique: true,
      trim: true,
      index: true, //enable opitimize searchable database
    },
    email: {
      type: String,
      required: true,
      lowercase: true,
      unique: true,
      trim: true,
    },

    password: {
      type: String,
      required: function (this: IUser) {
        //this refers to the document being saved.
        // Require password only if the user is NOT signing up with Google
        return !this.googleId;
      },
    },
    refreshToken: {
      type: String,
    },
    refreshTokenExpires: { type: Date },
    googleId: {
      type: String,
      unique: true,
      sparse: true, // allows null duplicates for googleId as not every usersigins with google
    },
    otp: {
      type: String,
    },
    otpExpires: {
      type: Date,
    },
  },
  { timestamps: true }
);

//before saving database pre hook used to encrypt or any  operation
//pre ma callback ()=>{} use nagarne cause this context won't work so use asyncfn
userSchema.pre<IUser>("save", async function (next) {
  if (!this.isModified("password") || !this.password) return next();

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});
//custom methods isPasswordCorrect
//bcrypt libary can hash and also can check original pw  not hashed pw or simply compare(bcrypt method)
userSchema.methods.isPasswordCorrect = async function (password: string) {
  if (!this.password) return false;
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this.id,
      email: this.email,
      username: this.username,
      type: "access",
    },
    process.env.ACCESS_TOKEN_SECRET as Secret,
    {
      expiresIn: (process.env.ACCESS_TOKEN_EXPIRY as string) || "15m",
    } as jwt.SignOptions
  );
};
userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this.id,
      type: "refresh",
    },
    process.env.REFRESH_TOKEN_SECRET as Secret,
    {
      expiresIn: (process.env.REFRESH_TOKEN_EXPIRY as string) || "7d",
    } as jwt.SignOptions
  );
};

export const User = mongoose.model("User", userSchema);
