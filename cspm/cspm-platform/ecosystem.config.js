module.exports = {
  apps: [
    { name: "alert-engine", script: "npm", args: "start", cwd: "./services/alert-engine" },
    { name: "billing-subscription", script: "npm", args: "start", cwd: "./services/billing-subscription" },
    { name: "cloud-connector", script: "npm", args: "start", cwd: "./services/cloud-connector" },
    { name: "compliance-engine", script: "npm", args: "start", cwd: "./services/compliance-engine" },
    { name: "data-security", script: "npm", args: "start", cwd: "./services/data-security" },
    { name: "drift-detection", script: "npm", args: "start", cwd: "./services/drift-detection" },
    { name: "inventory-collector", script: "npm", args: "start", cwd: "./services/inventory-collector" },
    { name: "misconfiguration-checker", script: "npm", args: "start", cwd: "./services/misconfiguration-checker" },
    { name: "threat-intelligence", script: "npm", args: "start", cwd: "./services/threat-intelligence" },
    { name: "user-management", script: "npm", args: "start", cwd: "./services/user-management", env: { PORT: 3012 } }, // Updated port
    { name: "frontend", script: "npm", args: "start", cwd: "./frontend" }
  ]
};