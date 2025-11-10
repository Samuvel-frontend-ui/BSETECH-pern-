const jwt = require("jsonwebtoken");
const pool = require("../db");

const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key";

async function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
//token
  if (!token) {
    return res.status(401).json({ message: "Access token missing" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const verify = await pool.query("SELECT * FROM users WHERE id = $1", [
      decoded.id,
    ]);

    if (!verify.rows || verify.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    
    req.user = verify.rows[0];
    
    next();
  } catch (err) {
    console.error("JWT verification error:", err);
    return res.status(403).json({ message: "Invalid or expired token" });
  }
}

module.exports = authenticateToken;
//this is the code of instagram
