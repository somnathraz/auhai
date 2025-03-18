const { Schema, model } = require("mongoose");

const apiKeySchema = new Schema({
  key: { type: String, required: true, unique: true },
  userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
  createdAt: { type: Date, default: Date.now },
  revoked: { type: Boolean, default: false },
  // You can add additional fields like "name", "description", "usageLimits", etc.
});

module.exports = model("ApiKey", apiKeySchema);
