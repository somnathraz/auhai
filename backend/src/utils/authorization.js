// src/utils/authorization.js
module.exports.checkRole = (user, allowedRoles) => {
  if (!user || !allowedRoles.includes(user.role)) {
    throw new Error("Not authorized to perform this action.");
  }
};
