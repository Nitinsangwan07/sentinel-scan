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
    passwordHash: user.passwordHash || null,
    authProvider: user.authProvider || "local",
    googleId: user.googleId || null,
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

  async findByGoogleId(googleId) {
    if (appConfig.storageMode === "mongo") {
      return normalizeUser(await UserModel.findOne({ googleId }));
    }

    const users = await getFallbackCollection("users");
    return normalizeUser(users.find((user) => user.googleId === googleId));
  },

  async findById(id) {
    if (appConfig.storageMode === "mongo") {
      return normalizeUser(await UserModel.findById(id));
    }

    const users = await getFallbackCollection("users");
    return normalizeUser(users.find((user) => user.id === id));
  },

  async create({ name, email, passwordHash = null, authProvider = "local", googleId = null }) {
    if (appConfig.storageMode === "mongo") {
      return normalizeUser(await UserModel.create({ name, email, passwordHash, authProvider, googleId }));
    }

    const users = await getFallbackCollection("users");
    const nextUser = {
      id: createFallbackId(),
      name,
      email: email.toLowerCase(),
      passwordHash,
      authProvider,
      googleId,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    await setFallbackCollection("users", [nextUser, ...users]);
    return normalizeUser(nextUser);
  },

  async updateIdentity(id, updates) {
    if (appConfig.storageMode === "mongo") {
      const nextUpdates = { ...updates };

      if (nextUpdates.email) {
        nextUpdates.email = nextUpdates.email.toLowerCase();
      }

      return normalizeUser(await UserModel.findByIdAndUpdate(id, { $set: nextUpdates }, { new: true }));
    }

    const users = await getFallbackCollection("users");
    const nextUsers = users.map((user) =>
      user.id === id
        ? {
            ...user,
            ...updates,
            email: updates.email ? updates.email.toLowerCase() : user.email,
            updatedAt: new Date().toISOString(),
          }
        : user,
    );

    await setFallbackCollection("users", nextUsers);
    return normalizeUser(nextUsers.find((user) => user.id === id));
  },
};
