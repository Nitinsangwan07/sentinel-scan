import { createError } from "../utils/createError.js";

export function validateRequiredFields(fields) {
  return (request, response, next) => {
    const missing = fields.filter((field) => {
      const value = request.body?.[field];
      return value === undefined || value === null || String(value).trim() === "";
    });

    if (missing.length > 0) {
      next(createError(400, `Missing required field(s): ${missing.join(", ")}`));
      return;
    }

    next();
  };
}
