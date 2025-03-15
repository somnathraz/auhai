const AuditLog = require("./AuditLog");

const logEvent = async (action, userId = null, metadata = {}) => {
  try {
    await AuditLog.create({ action, userId, metadata });
    console.log(`Logged event: ${action} for user ${userId}`);
  } catch (error) {
    console.error("Error logging event:", error);
  }
};

module.exports = { logEvent };
