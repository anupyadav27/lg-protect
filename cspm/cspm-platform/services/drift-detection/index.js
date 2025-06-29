const express = require('express');
const execSync = require('child_process').execSync;

const app = express();
const PORT = process.env.PORT || 3116; // Updated port

function freePort(port) {
  try {
    const result = execSync(`lsof -i :${port} -t`).toString();
    const pids = result.split('\n').filter(Boolean);
    pids.forEach(pid => execSync(`kill -9 ${pid}`));
    console.log(`Freed port ${port}`);
  } catch (error) {
    console.log(`Port ${port} is already free or could not be freed.`);
  }
}

freePort(PORT);

app.get('/', (req, res) => {
  res.send('Drift Detection Service is running');
});

app.listen(PORT, () => {
  console.log(`Drift Detection Service is running on port ${PORT}`);
});