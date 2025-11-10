const pool = require("../db");

/**
 * @swagger
 * tags:
 *   - name: Posts
 *     description: User posts management endpoints
 */

/**
 * @swagger
 * /posts:
 *   post:
 *     summary: Create a new post with videos
 *     tags: [Posts]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required:
 *               - description
 *               - videos
 *             properties:
 *               description:
 *                 type: string
 *                 example: "Check out this amazing video!"
 *               videos:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: binary
 *                 description: Array of video files
 *     responses:
 *       201:
 *         description: Post created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Post uploaded successfully!
 *                 post:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                       example: 1
 *                     user_id:
 *                       type: integer
 *                       example: 1
 *                     description:
 *                       type: string
 *                       example: "Check out this amazing video!"
 *                     videos:
 *                       type: array
 *                       items:
 *                         type: string
 *                         example: "/uploads/video123.mp4"
 *                     created_at:
 *                       type: string
 *                       format: date-time
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Description and videos are required.
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *       500:
 *         description: Server error
 */

exports.createUserPost = async (req, res) => {
  try {
    const userId = req.user.id; // from token
    const { description } = req.body;
    const videos = req.files.map((file) => `/uploads/${file.filename}`);

    if (!description || videos.length === 0) {
      return res.status(400).json({ message: "Description and videos are required." });
    }

    const result = await pool.query(
      `INSERT INTO user_posts (user_id, description, video) VALUES ($1, $2, $3) RETURNING *`,
      [userId, description, videos]
    );

    res.status(201).json({
      message: "Post uploaded successfully!",
      post: result.rows[0],
    });
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({ message: "Server error while uploading post." });
  }
};

/**
 * @swagger
 * /getpost:
 *   get:
 *     summary: Get all user posts with user information
 *     tags: [Posts]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Posts retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   post_id:
 *                     type: integer
 *                     example: 1
 *                   description:
 *                     type: string
 *                     example: "Check out this amazing video!"
 *                   videos:
 *                     type: array
 *                     items:
 *                       type: string
 *                       example: "/uploads/video123.mp4"
 *                   created_at:
 *                     type: string
 *                     format: date-time
 *                     example: "2024-01-15T10:30:00.000Z"
 *                   user_id:
 *                     type: integer
 *                     example: 1
 *                   name:
 *                     type: string
 *                     example: "John Doe"
 *                   profile_pic:
 *                     type: string
 *                     example: "/uploads/profile123.jpg"
 *       500:
 *         description: Server error
 */

exports.getUserPosts = async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         up.id AS post_id,
         up.description,
         up.video,
         up.created_at,
         u.id AS user_id,
         u.name,
         u.profile_pic
       FROM user_posts up
       JOIN users u ON up.user_id = u.id
       ORDER BY up.created_at DESC`
    );

    res.status(200).json(result.rows);
  } catch (error) {
    console.error("Fetch posts error:", error);
    res.status(500).json({ message: "Server error while fetching posts." });
  }
};

