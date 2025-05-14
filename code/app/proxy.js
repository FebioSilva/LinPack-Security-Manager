const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/sparql', async (req, res) => {
  const query = req.query.query;
  if (!query) {
    return res.status(400).json({ error: 'Query não fornecida' });
  }

  try {
    const response = await fetch('http://localhost:8890/sparql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/sparql-results+json',
      },
      body: `query=${encodeURIComponent(query)}`
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Erro do Virtuoso:', errorText);
      return res.status(response.status).json({ error: 'Erro ao buscar do Virtuoso', details: errorText });
    }

    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('Erro:', error);
    res.status(500).json({ error: 'Erro interno ao buscar do Virtuoso' });
  }
});

app.listen(3001, () => {
  console.log('🟢 Proxy rodando em http://localhost:3001');
});
