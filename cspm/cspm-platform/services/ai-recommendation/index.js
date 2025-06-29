const express = require('express');
const app = express();
const PORT = process.env.PORT || 3004;

app.get('/', (req, res) => {
  res.send('AI Recommendation Service is running');
});

app.listen(PORT, () => {
  console.log(`AI Recommendation Service is running on port ${PORT}`);
});