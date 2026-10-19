// rempart-expect: SEC-STRIPE-LIVE
const stripe = require("stripe")("{{FAKE_STRIPE_LIVE}}");
// rempart-expect: SEC-OPENAI-KEY
const openaiKey = "{{FAKE_OPENAI}}";
// rempart-safe: SEC-STRIPE-LIVE, SEC-OPENAI-KEY, SEC-GENERIC
const fromEnv = process.env.STRIPE_SECRET_KEY;
module.exports = { stripe, openaiKey, fromEnv };
