import { createError } from "../utils/createError.js";
import { decodeToken } from "../utils/auth.js";
import { userRepository } from "../repositories/userRepository.js";

function extractBearerToken(request) {
  const authHeader = request.headers.authorization || "";

  if (!authHeader.startsWith("Bearer ")) {
    return null;
  }

  return authHeader.slice("Bearer ".length).trim();
}

export async function authenticate(request, response, next) {
  try {
    const token = extractBearerToken(request);

    if (!token) {
      throw createError(401, "Authentication token is required.");
    }

    const payload = decodeToken(token);
    const user = await userRepository.findById(payload.sub);

    if (!user) {
      throw createError(401, "The account associated with this token no longer exists.");
    }

    request.user = {
      id: user.id,
      email: user.email,
      name: user.name,
    };
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      next(createError(401, "Your session has expired. Please sign in again."));
      return;
    }

    next(createError(401, "Invalid or expired token."));
  }
}