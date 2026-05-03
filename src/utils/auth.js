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
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
    },
    appConfig.jwtSecret,
    {
      expiresIn: appConfig.jwtExpiresIn,
    },
  );
}
