import dotenv from "dotenv";

dotenv.config();

function toNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export const appConfig = {
  port: toNumber(process.env.PORT, 3000),
  nodeEnv: process.env.NODE_ENV || "development",
  mongoUri: process.env.MONGODB_URI || "",
  jwtSecret: process.env.JWT_SECRET || "change-me-in-production",
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || "8h",
  corsOrigin: process.env.CORS_ORIGIN || "*",
  storageMode: process.env.MONGODB_URI ? "mongo" : "json-fallback",
  aiProvider: process.env.AI_PROVIDER || "heuristic",
  aiApiKey: process.env.AI_API_KEY || "",
  aiApiUrl: process.env.AI_API_URL || "",
};
