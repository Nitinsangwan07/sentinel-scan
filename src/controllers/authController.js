import { appConfig } from "../config/env.js";
import { loginUser, loginWithGoogle, signupUser } from "../services/authService.js";
import { asyncHandler } from "../utils/asyncHandler.js";

export const signup = asyncHandler(async (request, response) => {
  const result = await signupUser(request.body);
  response.status(201).json(result);
});

export const login = asyncHandler(async (request, response) => {
  const result = await loginUser(request.body);
  response.json(result);
});

export const googleLogin = asyncHandler(async (request, response) => {
  const result = await loginWithGoogle(request.body.idToken);
  response.json(result);
});

export const me = asyncHandler(async (request, response) => {
  response.json({
    user: request.user,
  });
});

export const authConfig = asyncHandler(async (request, response) => {
  response.set("Cache-Control", "no-store");
  response.json({
    googleClientId: appConfig.googleClientId || "",
    googleEnabled: Boolean(appConfig.googleClientId),
  });
});
