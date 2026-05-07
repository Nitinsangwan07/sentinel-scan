import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 80,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
      match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Invalid email address."],
    },

    passwordHash: {
      type: String,
      default: null,
    },

    authProvider: {
      type: String,
      enum: ["local", "google"],
      default: "local",
    },

    googleId: {
      type: String,
      default: null,
      unique: true,
      sparse: true,
    },
  },
  {
    timestamps: true,
    toJSON: {
      transform(document, returnedObject) {
        delete returnedObject.passwordHash;
        delete returnedObject.__v;
        return returnedObject;
      },
    },
    toObject: {
      transform(document, returnedObject) {
        delete returnedObject.passwordHash;
        delete returnedObject.__v;
        return returnedObject;
      },
    },
  },
);

export const UserModel =
  mongoose.models.User || mongoose.model("User", userSchema);