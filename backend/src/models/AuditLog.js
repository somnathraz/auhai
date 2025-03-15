const { Schema, model } = require("mongoose");

const auditLogSchema = new Schema({
  action: { type: String, required: true }, // e.g., "LOGIN", "SIGNUP", "UPDATE_ROLE", etc.
  userId: { type: Schema.Types.ObjectId, ref: "User", required: false },
  metadata: { type: Schema.Types.Mixed }, // Additional details (e.g., IP address, device info)
  timestamp: { type: Date, default: Date.now },
});

module.exports = model("AuditLog", auditLogSchema);
