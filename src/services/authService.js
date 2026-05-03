import { userRepository } from "../repositories/userRepository.js";
import { createError } from "../utils/createError.js";
import { hashPassword, issueToken, verifyPassword } from "../utils/auth.js";

function sanitizeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt,
  };
}

export async function signupUser({ name, email, password }) {
  const normalizedEmail = String(email).trim().toLowerCase();
  const existing = await userRepository.findByEmail(normalizedEmail);

  if (existing) {
    throw createError(409, "An account with this email already exists.");
  }

  const passwordHash = await hashPassword(password);
  const user = await userRepository.create({
    name: String(name).trim(),
    email: normalizedEmail,
    passwordHash,
  });

  return {
    token: issueToken(user),
    user: sanitizeUser(user),
  };
}

export async function loginUser({ email, password }) {
  const normalizedEmail = String(email).trim().toLowerCase();
  const user = await userRepository.findByEmail(normalizedEmail);

  if (!user) {
    throw createError(401, "Invalid email or password.");
  }

  const passwordMatches = await verifyPassword(password, user.passwordHash);

  if (!passwordMatches) {
    throw createError(401, "Invalid email or password.");
  }

  return {
    token: issueToken(user),
    user: sanitizeUser(user),
  };
}
