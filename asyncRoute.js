// Express 4 doesn't catch a rejected promise from an async
// handler/middleware — an unhandled rejection would otherwise hang the
// request instead of returning an error. Wrap every async
// handler/middleware with this so a thrown/rejected error reaches
// Express's error-handling middleware instead.
export const asyncRoute = handler => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
