import { appConfig } from "../config/env.js";
import { UserModel } from "../models/User.js";
import {
  createFallbackId,
  getFallbackCollection,
  setFallbackCollection,
} from "../services/fallbackStoreService.js";

async function normalizeUser(user) {
  if (!user) {
    return null;
  }

  return {
    id: String(user._id || user.id),
    name: user.name,
    email: user.email,
    passwordHash: user.passwordHash,
    createdAt: user.createdAt,
  };
}

export const userRepository = {
  async findByEmail(email) {
    if (appConfig.storageMode === "mongo") {
      return normalizeUser(await UserModel.findOne({ email: email.toLowerCase() }));
    }

    const users = await getFallbackCollection("users");
    return normalizeUser(users.find((user) => user.email === email.toLowerCase()));
  },

  async findById(id) {
    if (appConfig.storageMode === "mongo") {
      return normalizeUser(await UserModel.findById(id));
    }

    const users = await getFallbackCollection("users");
    return normalizeUser(users.find((user) => user.id === id));
  },

  async create({ name, email, passwordHash }) {
    if (appConfig.storageMode === "mongo") {
      return normalizeUser(await UserModel.create({ name, email, passwordHash }));
    }

    const users = await getFallbackCollection("users");
    const nextUser = {
      id: createFallbackId(),
      name,
      email: email.toLowerCase(),
      passwordHash,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    await setFallbackCollection("users", [nextUser, ...users]);
    return normalizeUser(nextUser);
  },
};
