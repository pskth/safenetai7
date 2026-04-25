require('dotenv').config();
const express = require("express");
const axios = require("axios");
const twilio = require("twilio");

const app = express();
app.use(express.urlencoded({ extended: false }));

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID || 'AC_dummy', process.env.TWILIO_AUTH_TOKEN || 'dummy');

app.post("/webhook", (req, res) => {
    console.log("=== Received Webhook from Twilio ===");
    console.log("Body:", req.body);

    const message = req.body.Body || "";
    const sender = req.body.From;

    if (!message) {
        console.log("Empty message, asking for text.");
        return sendReply(res, "Please send a text message");
    }

    // 1. Send "Please wait..." immediately
    sendReply(res, "Please wait...");

    // 2. Process message in background
    processMessageInBackground(message, sender).catch(err => {
        console.error("Error in background processing:", err);
    });
});

async function processMessageInBackground(message, sender) {
    try {
        const response = await axios.post("http://localhost:4000/api", {
            message: message,
            user: sender
        }, { timeout: 8000 });

        const reply = response.data.reply || "No response";

        // Push the processed message via Twilio API
        await twilioClient.messages.create({
            body: reply,
            from: process.env.TWILIO_WHATSAPP_NUMBER || "whatsapp:+14155238886", // Default Twilio Sandbox number
            to: sender
        });
        console.log("Successfully sent the processed reply:", reply);

    } catch (error) {
        console.error("Error from backend:", error.message);
        
        // Notify the user about the error
        await twilioClient.messages.create({
            body: "Sorry, there was an error processing your request.",
            from: process.env.TWILIO_WHATSAPP_NUMBER || "whatsapp:+14155238886",
            to: sender
        }).catch(e => console.error("Could not send error message to user:", e));
    }
}

function sendReply(res, text) {
    res.set("Content-Type", "text/xml");
    res.send(`
        <Response>
            <Message>${text}</Message>
        </Response>
    `);
}

app.listen(5000, () => {
    console.log("Webhook server running on port 5000");
});
