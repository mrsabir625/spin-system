// Spin World Ceiling System — AI Agent backend
// Proxies chat messages to Groq's free-tier API (keeps your API key hidden from the website).

require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.1-8b-instant';

const SYSTEM_PROMPT = `You are the AI assistant on the Spin World Ceiling System website — a POP (Plaster of Paris) false ceiling contractor business based in Telangana, India.

What you help with:
1. Explaining how the website works: visitors can click Hall, Bedroom, or Porch to open a photo gallery, tap photos to select their favorite designs, and send the selected list directly to the owner on WhatsApp using the floating "Send on WhatsApp" button.
2. Answering general questions about POP false ceilings: design styles, cove/coffer lighting, gypsum board vs POP, ceiling maintenance, how long installation typically takes, and what factors affect cost (materials, ceiling area, design complexity, lighting) — WITHOUT quoting specific prices, since pricing depends on site visit and is decided by the owner.
3. If someone asks for a quote, exact price, or wants to book a visit, tell them to send their shortlist via the website's WhatsApp button or message +91 88865 87534 directly.

Keep answers short (2-4 sentences), friendly, and in the same language style the visitor uses (Hindi/Hinglish or English). Do not invent company policies, warranty terms, or prices you don't know.`;

app.post('/api/chat', async (req, res) => {
  try {
    const { message, history } = req.body;
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ error: 'message is required' });
    }
    if (!GROQ_API_KEY) {
      return res.status(500).json({ error: 'Server not configured: GROQ_API_KEY missing in .env' });
    }

    const messages = [
      { role: 'system', content: SYSTEM_PROMPT },
      ...(Array.isArray(history) ? history.slice(-10) : []),
      { role: 'user', content: message }
    ];

    const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROQ_API_KEY}`
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        messages,
        temperature: 0.6,
        max_tokens: 300
      })
    });

    if (!groqRes.ok) {
      const errText = await groqRes.text();
      console.error('Groq API error:', errText);
      return res.status(502).json({ error: 'AI service error' });
    }

    const data = await groqRes.json();
    const reply = data.choices?.[0]?.message?.content?.trim() || "Sorry, I couldn't generate a reply.";
    res.json({ reply });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AI agent server running on http://localhost:${PORT}`));
