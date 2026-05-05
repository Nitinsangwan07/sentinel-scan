import { OAuth2Client } from "google-auth-library";

import { appConfig } from "../config/env.js";
import { userRepository } from "../repositories/userRepository.js";
import { createError } from "../utils/createError.js";
import { hashPassword, issueToken, verifyPassword } from "../utils/auth.js";

const googleClient = appConfig.googleClientId ? new OAuth2Client(appConfig.googleClientId) : null;

function sanitizeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    authProvider: user.authProvider || "local",
    createdAt: user.createdAt,
  };
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function validateName(name) {
  const normalized = String(name || "").trim();

  if (normalized.length < 2) {
    throw createError(400, "Name must be at least 2 characters long.");
  }

  return normalized;
}

function validatePassword(password) {
  const normalized = String(password || "");

  if (normalized.length < 8) {
    throw createError(400, "Password must be at least 8 characters long.");
  }

  return normalized;
}

export async function signupUser({ name, email, password }) {
  const normalizedEmail = normalizeEmail(email);
  const existing = await userRepository.findByEmail(normalizedEmail);

  if (existing) {
    throw createError(409, "An account with this email already exists.");
  }

  const user = await userRepository.create({
    name: validateName(name),
    email: normalizedEmail,
    passwordHash: await hashPassword(validatePassword(password)),
    authProvider: "local",
  });

  return {
    token: issueToken(user),
    user: sanitizeUser(user),
  };
}

export async function loginUser({ email, password }) {
  const normalizedEmail = normalizeEmail(email);
  const user = await userRepository.findByEmail(normalizedEmail);

  if (!user) {
    throw createError(401, "Invalid email or password.");
  }

  if (!user.passwordHash) {
    throw createError(401, "This account uses Google sign-in. Continue with Google to access it.");
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

export async function loginWithGoogle(idToken) {
  if (!googleClient || !appConfig.googleClientId) {
    throw createError(400, "Google sign-in is not configured for this environment.");
  }

  if (!idToken) {
    throw createError(400, "Google identity token is required.");
  }

  let payload;

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: appConfig.googleClientId,
    });
    payload = ticket.getPayload();
  } catch {
    throw createError(401, "Google sign-in could not be verified.");
  }

  const googleId = payload?.sub;
  const email = normalizeEmail(payload?.email);
  const name = String(payload?.name || payload?.given_name || "Google User").trim();

  if (!googleId || !email) {
    throw createError(400, "Google account information was incomplete.");
  }

  let user = await userRepository.findByGoogleId(googleId);

  if (!user) {
    const existingByEmail = await userRepository.findByEmail(email);

    if (existingByEmail) {
      user = await userRepository.updateIdentity(existingByEmail.id, {
        googleId,
        authProvider: existingByEmail.authProvider === "local" ? "local" : "google",
        name: existingByEmail.name || name,
      });
    } else {
      user = await userRepository.create({
        name,
        email,
        authProvider: "google",
        googleId,
      });
    }
  }

  return {
    token: issueToken(user),
    user: sanitizeUser(user),
  };
}
