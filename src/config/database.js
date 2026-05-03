import mongoose from "mongoose";

import { appConfig } from "./env.js";

export async function connectDatabase() {
  if (appConfig.storageMode !== "mongo") {
    return {
      mode: "json-fallback",
    };
  }

  await mongoose.connect(appConfig.mongoUri, {
    autoIndex: true,
  });

  return {
    mode: "mongo",
  };
}
