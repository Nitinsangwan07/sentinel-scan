export function errorHandler(error, request, response, next) {
  const statusCode =
    Number.isInteger(error.statusCode) && error.statusCode >= 400 && error.statusCode < 600
      ? error.statusCode
      : 500;
  const exposeMessage = statusCode < 500 || process.env.NODE_ENV === "development";
  const body = {
    ok: false,
    error: exposeMessage ? error.message || "Internal server error." : "Internal server error.",
  };

  if (process.env.NODE_ENV === "development" && error.stack) {
    body.stack = error.stack;
  }

  response.status(statusCode).json(body);
}