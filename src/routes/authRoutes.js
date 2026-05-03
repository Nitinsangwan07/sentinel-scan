import { Router } from "express";

import { login, me, signup } from "../controllers/authController.js";
import { authenticate } from "../middleware/authMiddleware.js";
import { validateRequiredFields } from "../middleware/validateRequest.js";

const router = Router();

router.post("/signup", validateRequiredFields(["name", "email", "password"]), signup);
router.post("/login", validateRequiredFields(["email", "password"]), login);
router.get("/me", authenticate, me);

export default router;
