import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import { appConfig } from "../config/env.js";

export async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password, passwordHash) {
  return bcrypt.compare(password, passwordHash);
}

export function issueToken(user) {
  if (appConfig.isProduction && appConfig.jwtSecret.length < 32) {
    throw new Error("JWT_SECRET must be at least 32 characters long in production.");
  }

  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      provider: user.authProvider || "local",
    },
    appConfig.jwtSecret,
    {
      expiresIn: appConfig.jwtExpiresIn,
      algorithm: "HS256",
    },
  );
}

export function decodeToken(token) {
  return jwt.verify(token, appConfig.jwtSecret, {
    algorithms: ["HS256"],
  });
}