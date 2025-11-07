const pool = require("../db");

exports.createUserPost = async (req, res) => {
  try {
    const userId = req.user.id; // from token
    const { description } = req.body;
    const videos = req.files.map((file) => `/uploads/${file.filename}`);

    if (!description || videos.length === 0) {
      return res.status(400).json({ message: "Description and videos are required." });
    }

    const result = await pool.query(
      `INSERT INTO user_posts (user_id, description, videos) VALUES ($1, $2, $3) RETURNING *`,
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

exports.getUserPosts = async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         up.id AS post_id,
         up.description,
         up.videos,
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



