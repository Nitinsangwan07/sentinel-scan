import { Router } from "express";

import {
  createScan,
  getAiAssist,
  getScan,
  listScans,
} from "../controllers/scanController.js";
import { authenticate } from "../middleware/authMiddleware.js";
import { validateRequiredFields } from "../middleware/validateRequest.js";

const router = Router();

router.use(authenticate);
router.get("/", listScans);
router.post("/", validateRequiredFields(["url"]), createScan);
router.get("/:scanId", getScan);
router.get("/:scanId/ai", getAiAssist);

export default router;
