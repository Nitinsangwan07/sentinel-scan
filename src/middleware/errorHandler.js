export function errorHandler(error, request, response, next) {
  const statusCode = error.statusCode || 500;

  response.status(statusCode).json({
    error: error.message || "Internal server error.",
  });
}
