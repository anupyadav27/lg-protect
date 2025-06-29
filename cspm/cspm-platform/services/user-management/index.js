const express = require('express');
const execSync = require('child_process').execSync;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3120; // Updated port

app.use(express.json()); // Middleware to parse JSON bodies

// Enable CORS middleware
app.use(cors());

// Debugging middleware to log incoming requests
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`, req.body);
  next();
});

// In-memory storage for users
const users = [];

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
  res.send('User Management Service is running');
});

app.get('/api/users', (req, res) => {
  const usersList = [
    { id: 1, name: 'John Doe', email: 'john.doe@example.com' },
    { id: 2, name: 'Jane Smith', email: 'jane.smith@example.com' }
  ];
  res.json(usersList);
});

app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save the user to in-memory storage
    const newUser = { id: Date.now(), name, email, password: hashedPassword };
    users.push(newUser);
    console.log('User created:', newUser);

    res.status(201).json({ message: 'User created successfully', user: { id: newUser.id, name, email } });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    // Fetch the user from in-memory storage
    const user = users.find(u => u.email === username);

    console.log('Received username:', username);
    console.log('Stored user:', user);

    if (!user) {
      console.log('User not found');
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log('Password valid:', isPasswordValid);

    if (!isPasswordValid) {
      console.log('Invalid password');
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Generate a token (use a library like jsonwebtoken)
    const token = jwt.sign({ id: user.id, username: user.email }, 'secretKey', { expiresIn: '1h' });

    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`User Management Service is running on port ${PORT}`);
});