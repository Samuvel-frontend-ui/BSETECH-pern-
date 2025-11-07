require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs");
const db = require("./db");
const controlroute = require("./route/user");
const uploadpost= require("./route/upload")
const app = express();
const PORT = process.env.PORT || 5000;
const { specs, swaggerUi } = require('./swagger');

// Add this after initializing your express app
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" }));

app.use(express.json());   
app.use(cors());

app.get("/", (req, res) => res.json({ message: "API is running" }));

app.use("/", controlroute);

app.use("/", uploadpost);

app.use("/profile_pic", express.static(path.join(__dirname, "userprofilepic")));

app.use("/uploads", express.static(path.join(__dirname, "uploads")));
 
db.query("SELECT NOW()")
  .then(() => console.log("✅ Database connected"))
  .catch((err) => {
    console.error("❌ Database connection error:", err.message);
    process.exit(1);
  });

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
