const pool = require("../db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer= require("nodemailer");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const SALT_ROUNDS = 10;

const uploadDir = path.join(__dirname, "..", "userprofilepic");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + "-" + file.originalname;
    cb(null, uniqueName); 
  },
});

function fileFilter(req, file, cb) {
  if (file.mimetype === "image/jpeg" || file.mimetype === "image/png") {
    cb(null, true);
  } else {
    cb(new Error("Only JPEG or PNG files are allowed!"), false);
  }
}

const upload = multer({ storage, fileFilter });

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - password
 *               - phoneno
 *               - address
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               phoneno:
 *                 type: string
 *               address:
 *                 type: string
 *               accountType:
 *                 type: string
 *               profile_pic:
 *                 type: string
 *                 format: binary
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Validation error
 *       409:
 *         description: Email already registered
 *       500:
 *         description: Server error
 */

const registered = async (req, res) => {
  upload.single("profile_pic")(req, res, async (err) => {
    try {
      if (err) {
        console.error("Multer/Upload Error:", err);
        return res.status(400).json({
          message: "File upload failed",
          error: err.message || "Invalid file data.",
        });
      }

      const { name, address, email, password, phoneno, accountType } = req.body;

      if (!name || !email || !password || !phoneno || !address) {
        if (req.file) {
          fs.unlinkSync(req.file.path);
        }
        return res.status(400).json({ message: "All fields are required" });
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        if (req.file) {
          fs.unlinkSync(req.file.path);
        }
        return res.status(400).json({ message: "Invalid email format" });
      }

      const exists = await pool.query(
        "SELECT id FROM users WHERE email = $1", 
        [email]
      );
      
      if (exists.rows.length > 0) {
        if (req.file) {
          fs.unlinkSync(req.file.path);
        }
        return res.status(409).json({ message: "Email already registered" });
      }

      const hashed = await bcrypt.hash(password, SALT_ROUNDS);
      const profilePic = req.file ? req.file.filename : null;

      const result = await pool.query(
        `INSERT INTO users (name, email, password, address, profile_pic, phoneno, accounttype)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, name, email, address, profile_pic, phoneno, accounttype, created_at`,
        [name, email, hashed, address, profilePic, phoneno, accountType]
      );

      const user = result.rows[0];
      
      return res.status(201).json({
        message: "Registered successfully. Please log in.",
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          address: user.address,
          profile_pic: user.profile_pic,
          phoneno: user.phoneno,
          accountType: user.accounttype,
          created_at: user.created_at
        },
      });

    } catch (err) {
      if (req.file) {
        try {
          fs.unlinkSync(req.file.path);
        } catch (unlinkErr) {
          console.error("Error deleting file:", unlinkErr);
        }
      }
      console.error("Register error:", err.message);
      return res.status(500).json({ message: "Server error" });
    }
  });
};

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 token:
 *                   type: string
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                     name:
 *                       type: string
 *                     email:
 *                       type: string
 *                     profile_pic:
 *                       type: string
 *       400:
 *         description: Email and password required
 *       401:
 *         description: Invalid credentials
 *       500:
 *         description: Server error
 */

const logined = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ message: "User not found" });
    }

    const user = result.rows[0];
 
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: "Invalid password" });
    }
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, process.env.JWT_SECRET, { expiresIn: "24h" });

    return res.json({
      message: "Login successful",
      token,
      user: { id: user.id, name: user.name, email: user.email, profile_pic: user.profile_pic },
    });
  } catch (err) {
    console.error("Login error:", err.message);
    return res.status(500).json({ message: "Server error" });
  }
}

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/**
 * @swagger
 * /forgotpassword:
 *   post:
 *     summary: Request password reset
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *     responses:
 *       200:
 *         description: Reset link sent to email
 *       400:
 *         description: Email is required or invalid
 *       500:
 *         description: Server error
 */

const forgot_password = async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userResult.rows.length === 0)
      return res.status(400).json({ error: "Invalid userId" });

    const user = userResult.rows[0];
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    const expires = new Date(Date.now() + 3600000);

    await pool.query(
      "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
      [user.id, token, expires]
    );

    const resetLink = `http://localhost:5173/reset-password?token=${token}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: "Password Reset",
      html: `
        <p>We received a request to reset your password.</p>
        <p><a href="${resetLink}" style="background:#007bff;color:white;padding:10px 20px;text-decoration:none;">Reset Password</a></p>
        <p>If you didn’t request this, please ignore this email.</p>
      `,
    });

    res.json({ message: "Reset link sent to your email" });
  } 
  catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
}

/**
 * @swagger
 * /reset-password:
 *   post:
 *     summary: Reset password with token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *               - newPassword
 *             properties:
 *               token:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Password reset successfully
 *       400:
 *         description: Token and new password are required or token expired
 *       500:
 *         description: Server error
 */

const reset_password= async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword)
    return res.status(400).json({ error: "Token and new password are required" });

  try {
    const tokenResult = await pool.query(
      "SELECT * FROM password_reset_tokens WHERE token = $1 AND expires_at > NOW()",
      [token]
    );

    if (tokenResult.rows.length === 0)
      return res.status(400).json({ error: "Token has been expired try again the request" });

    const userId = tokenResult.rows[0].user_id;
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hashedPassword, userId]);
    await pool.query("DELETE FROM password_reset_tokens WHERE token = $1", [token]);

    res.json({ message: "Password reset successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
}

const parseIntParam = (param) => {
  const parsed = Number(param);
  return Number.isNaN(parsed) ? null : parsed;
};

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get paginated users list (excluding current user)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 6
 *         description: Number of users per page
 *     responses:
 *       200:
 *         description: Users retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 page:
 *                   type: integer
 *                 limit:
 *                   type: integer
 *                 users:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/User'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */

const getusers =  async (req, res) => {
  try {
  
    if (!req.user || !req.user.id) {
      return res.status(401).json({ message: "Unauthorized: user not found in token" });
    }

    const loggedInUserId = req.user.id;

    // Parse pagination params safely
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.max(1, parseInt(req.query.limit) || 6);
    const offset = (page - 1) * limit;

    const usersResult = await pool.query(
      `SELECT id, name, email, address, accounttype, profile_pic, created_at
       FROM users
       WHERE id != $1
       ORDER BY id ASC
       LIMIT $2 OFFSET $3`,
      [loggedInUserId, limit, offset]
    );

    res.json({
      page,
      limit,
      users: usersResult.rows || []
    });

  } catch (err) {
    console.error("Backend error fetching users:", err);
    res.status(500).json({ message: "Server error fetching users" });
  }
}

/**
 * @swagger
 * /follow:
 *   post:
 *     summary: Follow/unfollow user or send follow request
 *     tags: [Follow]
 * 
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/FollowAction'
 *     responses:
 *       200:
 *         description: Operation successful
 *       400:
 *         description: Missing or invalid fields
 *       500:
 *         description: Server error
 */

const followbutton = async (req, res) => {
  const { userId, targetId, action, isRequest } = req.body;
  const uid = parseIntParam(userId);
  const tid = parseIntParam(targetId);

  if (!uid || !tid || !action)
    return res.status(400).json({ success: false, message: "Missing or invalid fields" });

  try {
    const rejected = await pool.query(
      "SELECT * FROM follows WHERE user_id=$1 AND target_id=$2 AND status='rejected'",
      [uid, tid]
    );

    if (rejected.rows.length > 0) {
      await pool.query(
        "UPDATE follows SET status='pending', created_at=NOW() WHERE id=$1",
        [rejected.rows[0].id]
      );
      return res.json({ success: true, message: "Follow request sent again", status: "pending" });
    }

    if (action === "unfollow") {
      await pool.query("DELETE FROM follows WHERE user_id=$1 AND target_id=$2", [uid, tid]);
      return res.json({ success: true, message: "Unfollowed / Request cancelled" });
    }

    const status = isRequest ? "pending" : "accepted";

    const result = await pool.query(
      `INSERT INTO follows (user_id, target_id, status)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, target_id) DO NOTHING
       RETURNING *`,
      [uid, tid, status]
    );

    if (result.rowCount === 0)
      return res.json({ success: false, message: isRequest ? "Request already sent" : "Already following" });

    res.json({ success: true, message: isRequest ? "Follow request sent" : "Now following", status });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
}

/**
 * @swagger
 * /following/{userId}:
 *   get:
 *     summary: Get user's following list and pending requests
 *     tags: [Follow]
 *
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: integer
 *         description: User ID
 *     responses:
 *       200:
 *         description: Following data retrieved
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 following:
 *                   type: array
 *                   items:
 *                     type: integer
 *                 pendingRequests:
 *                   type: array
 *                   items:
 *                     type: integer
 *       400:
 *         description: Invalid userId
 *       500:
 *         description: Server error
 */

const following = async (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  if (!userId) return res.status(400).json({ error: "Invalid userId" });

  try {
    const result = await pool.query(
      "SELECT id, target_id, status FROM follows WHERE user_id = $1",
      [userId]
    );

    const following = result.rows.filter(r => r.status === "accepted").map(r => r.target_id);
    const pendingRequests = result.rows.filter(r => r.status === "pending").map(r => r.target_id);

    res.json({ following, pendingRequests });
  } catch (err) {
    console.error("Following route error:", err);
    res.status(500).json({ message: "Server error" });
  }
}

/**
 * @swagger
 * /profile/{id}:
 *   get:
 *     summary: Get user profile by ID
 *     tags: [Profile]
 * 
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: User ID
 *     responses:
 *       200:
 *         description: Profile retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       400:
 *         description: Invalid userId
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */

const profileget = async (req, res) => {
  const userId = parseInt(req.params.id, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: "Invalid userId" });
  }

  try {
    const [userResult, followersResult, followingResult] = await Promise.all([
      pool.query(
        `SELECT id, name AS username, email, profile_pic, accounttype, phoneno, address
         FROM users WHERE id = $1`,
        [userId]
      ),
      pool.query(
        `SELECT COUNT(*) AS total 
         FROM follows f
         WHERE f.target_id = $1 AND f.status='accepted'`,
        [userId]
      ),
      pool.query(
        `SELECT COUNT(*) AS total 
         FROM follows f
         WHERE f.user_id = $1 AND f.status='accepted'`,
        [userId]
      ),
    ]);

    if (!userResult.rows.length) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = userResult.rows[0];
    user.accountType = user.accounttype;
    user.phoneNo = user.phoneno || "";
    user.FollowersCount = parseInt(followersResult.rows[0].total);
    user.FollowingCount = parseInt(followingResult.rows[0].total);

    res.status(200).json(user);
  } catch (err) {
    console.error("Get user error:", err.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

/**
 * @swagger
 * /api/profile/{id}:
 *   put:
 *     summary: Update user profile
 *     tags: [Profile]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: User ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               email:
 *                 type: string
 *               accountType:
 *                 type: string
 *               phoneNo:
 *                 type: string
 *               address:
 *                 type: string
 *               loggedInUserId:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Profile updated successfully
 *       400:
 *         description: Invalid data
 *       403:
 *         description: Can only update own profile
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */

const  profileupdate = async (req, res) => {
  const userId = parseIntParam(req.params.id, 10);
  const { username, email, accountType, phoneNo, address, loggedInUserId} = req.body;


  if (!userId || parseInt(loggedInUserId, 10) !== userId) {
    return res.status(403).json({ message: "You can only update your own profile" });
  }

  try {
    const result = await pool.query(
      `UPDATE users
       SET name=$1, email=$2, accounttype=$3, phoneno=$4, address=$5
       WHERE id=$6
       RETURNING id, name AS username, email, profile_pic, accounttype, phoneno, address`,
      [username, email, accountType, phoneNo, address, userId]
    );

    if (!result.rows.length)
      return res.status(404).json({ message: "User not found" });

    const updatedUser = result.rows[0];
    updatedUser.accountType = updatedUser.accounttype;
    updatedUser.phoneNo = updatedUser.phoneno;

    res.json(updatedUser);
  } catch (err) {
    console.error("Update user error:", err.message);
    res.status(500).json({ error: err.message });
  }
}

/**
 * @swagger
 * /followers/{userId}:
 *   get:
 *     summary: Get user's followers list with pagination
 *     tags: [Follow]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: integer
 *         description: User ID
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 3
 *         description: Number of followers per page
 *     responses:
 *       200:
 *         description: Followers list retrieved
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 page:
 *                   type: integer
 *                 limit:
 *                   type: integer
 *                 followers:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                       username:
 *                         type: string
 *                       profile_pic:
 *                         type: string
 *       400:
 *         description: Invalid userId
 *       500:
 *         description: Server error
 */

const followerslist = async (req, res) => {
  const userId = parseIntParam(req.params.userId);
  if (!userId) return res.status(400).json({ error: "Invalid userId" });

  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 3;
  const offset = (page - 1) * limit;

  try {
    const result = await pool.query(
        `SELECT u.id,u.name AS username,u.profile_pic
        FROM follows f
        JOIN users u ON f.user_id = u.id
        WHERE f.target_id = $1 AND f.status = 'accepted'
        ORDER BY u.id ASC
        LIMIT $2 OFFSET $3;`,
      [userId, limit, offset]
    );

    res.json({ page, limit, followers: result.rows });
  } catch (err) {
    console.error("Followers fetch error:", err.message);
    res.status(500).json({ error: err.message });
  }
}

/**
 * @swagger
 * /following-list/{userId}:
 *   get:
 *     summary: Get users that the specified user is following
 *     tags: [Follow]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: integer
 *         description: User ID
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 3
 *         description: Number of following users per page
 *     responses:
 *       200:
 *         description: Following list retrieved
 *       400:
 *         description: Invalid userId
 *       500:
 *         description: Server error
 */

const followinglist = async (req, res) => {
  const userId = parseIntParam(req.params.userId);
  if (!userId) return res.status(400).json({ error: "Invalid userId" });

  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 3;
  const offset = (page - 1) * limit;

  try {
    const result = await pool.query(
      `SELECT u.id,u.name AS username,u.profile_pic
        FROM follows f
        JOIN users u ON f.target_id = u.id
        WHERE f.user_id = $1 AND f.status = 'accepted'
        ORDER BY u.id ASC
        LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );

    res.json({ page, limit, following: result.rows });
  } catch (err) {
    console.error("Following fetch error:", err.message);
    res.status(500).json({ error: err.message });
  }
}

/**
 * @swagger
 * /follow-requests/{userId}:
 *   get:
 *     summary: Get pending follow requests for a user
 *     tags: [Follow]
 * 
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: integer
 *         description: User ID
 *     responses:
 *       200:
 *         description: Pending requests retrieved
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 pendingRequests:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                       requesterId:
 *                         type: integer
 *                       username:
 *                         type: string
 *                       profile_pic:
 *                         type: string
 *       400:
 *         description: Invalid userId
 *       500:
 *         description: Server error
 */

const followrequest = async (req, res) => {
  const userId = parseIntParam(req.params.userId);
  if (!userId) return res.status(400).json({ error: "Invalid userId" });

  try {
    const result = await pool.query(
      `SELECT f.id, f.user_id AS requesterId, u.name AS username, u.profile_pic
       FROM follows f
       JOIN users u ON f.user_id=u.id
       WHERE f.target_id=$1 AND f.status='pending'
       ORDER BY f.created_at ASC`,
      [userId]
    );

    res.json({ pendingRequests: result.rows });
  } catch (err) {
    console.error("Pending requests error:", err.message);
    res.status(500).json({ error: err.message });
  }
}

/**
 * @swagger
 * /follow-request/{requestId}:
 *   put:
 *     summary: Approve or reject follow request
 *     tags: [Follow]
 *     parameters:
 *       - in: path
 *         name: requestId
 *         required: true
 *         schema:
 *           type: integer
 *         description: Follow request ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - action
 *             properties:
 *               action:
 *                 type: string
 *                 enum: [approve, reject]
 *     responses:
 *       200:
 *         description: Request handled successfully
 *       400:
 *         description: Invalid request
 *       404:
 *         description: Follow request not found
 *       500:
 *         description: Server error
 */

const followreqhandle = async (req, res) => {
  const requestId = parseIntParam(req.params.requestId);
  ownerId = req.user.id;
  const {action } = req.body;

  if (!requestId || !ownerId || !["approve", "reject"].includes(action)) {
    return res.status(400).json({ message: "Invalid request" });
  }

  const statusToUpdate = action === "approve" ? "accepted" : "rejected";

  try {
    const result = await pool.query(
      `UPDATE follows SET status=$1, created_at=NOW()
       WHERE id=$2 AND target_id=$3
       RETURNING *`,
      [statusToUpdate, requestId, ownerId]
    );

    if (!result.rows.length)
      return res.status(404).json({ message: "Follow request not found" });

    res.json({ message: action === "approve" ? "Request approved" : "Request rejected" });
  } catch (err) {
    console.error("Handle follow request error:", err.message);
    res.status(500).json({ error: err.message });
  }
}

module.exports= { 
  registered,
    logined, 
    forgot_password, 
    reset_password, 
    getusers, 
    followbutton, 
    following, 
    profileget,  
    profileupdate, 
    followerslist,
    followinglist,
    followrequest,
    followreqhandle,

};