import mongoose from "mongoose";
import process from "node:process";

import app from "./app.js";
import { appConfig } from "./config/env.js";
import { connectDatabase } from "./config/database.js";

let server;

function validateStartupConfig() {
  if (appConfig.isProduction) {
    if (appConfig.jwtSecret.length < 32) {
      throw new Error("JWT_SECRET must be at least 32 characters long in production.");
    }

    if (!appConfig.mongoUri) {
      throw new Error("MONGODB_URI is required in production.");
    }
  }
}

async function shutdown(signal) {
  console.log(`${signal} received, shutting down Sentinel Scan gracefully...`);

  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }

  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
  }

  process.exit(0);
}

async function startServer() {
  try {
    validateStartupConfig();
    await connectDatabase();

    server = app.listen(appConfig.port, () => {
      console.log(
        `Sentinel Scan running on http://localhost:${appConfig.port} using ${appConfig.storageMode} storage`,
      );
    });
  } catch (error) {
    console.error("Unable to start Sentinel Scan:", error);
    process.exit(1);
  }
}

process.on("SIGINT", () => {
  shutdown("SIGINT").catch((error) => {
    console.error("Forced shutdown after SIGINT failure:", error);
    process.exit(1);
  });
});

process.on("SIGTERM", () => {
  shutdown("SIGTERM").catch((error) => {
    console.error("Forced shutdown after SIGTERM failure:", error);
    process.exit(1);
  });
});

process.on("unhandledRejection", (error) => {
  console.error("Unhandled promise rejection:", error);
});

process.on("uncaughtException", (error) => {
  console.error("Uncaught exception:", error);
  process.exit(1);
});

startServer();