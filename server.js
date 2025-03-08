const express = require('express');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const dotenv = require('dotenv');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Setup Google Generative AI
let apiKey;
try {
    // First try to get the API key from Render secrets
    apiKey = fs.readFileSync('/etc/secrets/GOOGLE_API_KEY', 'utf8').trim();
    console.log('API key loaded from Render secrets');
} catch (error) {
    // Fall back to environment variable
    apiKey = process.env.GOOGLE_API_KEY;
    console.log('API key loaded from environment variable');
}

// Initialize the Generative AI API
const genAI = new GoogleGenerativeAI(apiKey);

// Initialize the model
const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });

// API endpoint for generating responses
app.post('/api/generate', async (req, res) => {
    try {
        const { message } = req.body;
        
        if (!message) {
            return res.status(400).json({ error: 'Message is required' });
        }

        // Prepare the prompt
        const prompt = `You are Ducky, a friendly and playful duck assistant who loves to make duck-themed puns and says "quack" occasionally. Keep responses cheerful and duck-themed!

User's message: ${message}

Please respond in a cheerful, duck-themed way.`;

        console.log('Sending prompt to Gemini...');
        const result = await model.generateContent(prompt);
        console.log('Received response from Gemini');
        
        const response = await result.response;
        const text = response.text();
        
        console.log('Generated response:', text);
        res.json({ response: text });
    } catch (error) {
        console.error('Detailed Server Error:', {
            message: error.message,
            stack: error.stack,
            name: error.name
        });
        
        // Check if it's a safety error
        if (error.message?.includes('safety')) {
            return res.status(400).json({
                error: 'Content filtered for safety',
                details: error.message
            });
        }
        
        // Check for API key errors
        if (error.message?.includes('API key')) {
            return res.status(401).json({
                error: 'API key error',
                details: error.message
            });
        }
        
        res.status(500).json({ 
            error: 'Failed to generate response',
            details: error.message 
        });
    }
});

const PORT = process.env.PORT || 3001;

const startServer = () => {
    const server = app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    }).on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.error(`Port ${PORT} is busy. Trying port ${PORT + 1}`);
            setTimeout(() => {
                server.close();
                app.listen(PORT + 1, () => {
                    console.log(`Server running on port ${PORT + 1}`);
                });
            }, 1000);
        } else {
            console.error('Server error:', err);
        }
    });
};

startServer();