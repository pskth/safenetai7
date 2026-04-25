const express = require("express");
const axios = require("axios");

const app = express();
app.use(express.json());

const ML_API_URL = "http://localhost:8000/scan/offer/";

app.post("/api", async (req, res) => {
    const { message, user } = req.body;

    let reply;

    if (!message) {
        return res.json({ reply: "Please send a message to analyze." });
    }

    // Basic heuristic to check if it looks like a general greeting or an offer/email to scan
    if (message.toLowerCase().trim() === "hello" || message.toLowerCase().trim() === "hi") {
        reply = "Hi! Send me an internship offer or email text, and I'll tell you if it's safe or a scam.";
        return res.json({ reply });
    }

    try {
        // Send the message to the AI model
        const response = await axios.post(ML_API_URL, {
            message: message
        });

        const data = response.data;
        const { is_offer, prediction, confidence, red_flags } = data;

        if (!is_offer) {
            reply = "🤖 This message doesn't look like an internship or job offer.\n\nI'm designed to analyze internship and job offer messages for scams. Try sending me a job/internship offer message!";
        } else if (prediction === "Fake") {
            reply = `⚠️ *SCAM ALERT*\n\nThis offer looks suspiciously like a scam. I am ${confidence}% confident it's fake.\n\n`;
            if (red_flags && red_flags.length > 0) {
                reply += `*Red Flags Found:*\n- ${red_flags.join("\n- ")}\n\n`;
            }
            reply += "Please do not click on any links or pay any fees. Be safe!";
        } else {
            reply = `✅ *SAFE*\n\nThis looks like a legitimate offer. I am ${confidence}% confident it's safe. However, always verify the sender's official email and company website before accepting.`;
        }
    } catch (error) {
        console.error("Error communicating with ML API:", error.message);
        reply = "I'm having trouble analyzing this right now. Please try again later.";
    }

    res.json({ reply: reply });
});

app.listen(4000, () => {
    console.log("Backend API running on port 4000");
});
