const express = require('express');
const execSync = require('child_process').execSync;
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000; // Updated port to 4000

// Enable CORS
app.use(cors());

// Add X-Total-Count header and expose it in CORS
app.use((req, res, next) => {
  res.setHeader('Access-Control-Expose-Headers', 'X-Total-Count');
  next();
});

// Sample JSON data for misconfigurations
const misconfigurations = [
  {
    rule_number: 1,
    "Compliance committee": "AWS",
    "Compliance ID": "CIS-1.1",
    "Compliance Name": "Ensure MFA is enabled",
    "Compliance Description": "Multi-factor authentication should be enabled for all IAM users.",
    "Compliance Function Name": "checkMFA",
    "Required API client": "IAM",
    "Required Boto3 user function": "get_iam_users"
  },
  {
    rule_number: 2,
    "Compliance committee": "AWS",
    "Compliance ID": "CIS-1.2",
    "Compliance Name": "Ensure S3 buckets are private",
    "Compliance Description": "All S3 buckets should have private access policies.",
    "Compliance Function Name": "checkS3Privacy",
    "Required API client": "S3",
    "Required Boto3 user function": "get_s3_buckets"
  }
];

// Function to free up the port
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

// Free the port before starting the server
freePort(PORT);

// API endpoint to fetch misconfigurations
app.get('/api/misconfigurations', (req, res) => {
  res.setHeader('X-Total-Count', misconfigurations.length);
  res.json(misconfigurations);
});

// Health check endpoint
app.get('/', (req, res) => {
  res.send('Misconfiguration Checker Service is running');
});

// Endpoint to fetch compliance data from JSON file
app.get('/api/compliance-data', (req, res) => {
  const filePath = path.join(__dirname, 'output', 'AWS_compliance_information.json');
  const page = parseInt(req.query.page) || 1; // Default to page 1
  const limit = parseInt(req.query.limit) || 10; // Default to 10 items per page

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      console.error('Error reading file:', err);
      res.status(500).send('Error reading file');
    } else {
      try {
        const complianceData = JSON.parse(data); // Parse the entire JSON file
        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + limit;
        const paginatedData = complianceData.slice(startIndex, endIndex).map((item) => ({
          id: item.rule_number, // Use rule_number as the unique id
          ...item
        }));

        res.setHeader('X-Total-Count', complianceData.length); // Set total count header
        res.json({
          data: paginatedData, // Wrap data in a data object
          total: complianceData.length // Include total count
        });
      } catch (parseError) {
        console.error('Error parsing JSON:', parseError);
        res.status(500).send('Error parsing JSON file');
      }
    }
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Misconfiguration Checker Service is running on port ${PORT}`);
});