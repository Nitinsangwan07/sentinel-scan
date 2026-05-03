import { Router } from "express";

import { downloadReport } from "../controllers/reportController.js";
import { authenticate } from "../middleware/authMiddleware.js";

const router = Router();

router.use(authenticate);
router.get("/:scanId/:format", downloadReport);

export default router;
