import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import DOMPurify from "dompurify";

export default function VideoFeed() {
  const [posts, setPosts] = useState([]);
  const navigate = useNavigate();

  // ✅ Fetch posts from backend
  useEffect(() => {
    const fetchPosts = async () => {
      try {
        const res = await axios.get("http://localhost:5000/getpost");
        setPosts(res.data);
      } catch (err) {
        console.error("Error fetching posts:", err);
      }
    };
    fetchPosts();
  }, []);

  return (
    <div className="container py-4">
      {/* Header */}
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2 className="fw-bold text-primary mb-0">📹 Latest Video Posts</h2>
        <button
          className="btn btn-primary rounded-pill px-4 fw-semibold"
          onClick={() => navigate("/post")}
        >
          ➕ Upload Post
        </button>
      </div>

      {/* Posts Section */}
      {posts.length === 0 ? (
        <p className="text-center text-muted">No posts found.</p>
      ) : (
        <div className="row justify-content-center">
          <div className="col-md-8">
            {posts.map((post) => (
              <div
                key={post.post_id}
                className="card mb-4 border-0 shadow-sm rounded-4 overflow-hidden"
              >
                {/* Profile Header */}
                <div className="card-header bg-white border-0 d-flex align-items-center py-3">
                  <img
                    src={
                      post.profile_pic
                        ? `http://localhost:5000/profile_pic/${post.profile_pic}`
                        : "https://via.placeholder.com/50"
                    }
                    alt="Profile"
                    className="rounded-circle me-3 border border-2 border-primary-subtle"
                    width="55"
                    height="55"
                    style={{ objectFit: "cover" }}
                  />
                  <div>
                    <h6 className="mb-0 fw-semibold text-dark">{post.name}</h6>
                    <small className="text-muted">
                      {new Date(post.created_at).toLocaleString()}
                    </small>
                  </div>
                </div>

                {/* ✅ Video Carousel */}
                {Array.isArray(post.videos) && post.videos.length > 0 && (
                  <div
                    id={`carousel-${post.post_id}`}
                    className="carousel slide"
                    data-bs-ride="carousel"
                  >
                    <div className="carousel-inner ratio ratio-16x9 bg-dark">
                      {post.videos.map((video, index) => (
                        <div
                          key={index}
                          className={`carousel-item ${
                            index === 0 ? "active" : ""
                          }`}
                        >
                          <video
                            src={`http://localhost:5000${video}`}
                            className="d-block w-100"
                            controls
                          />
                        </div>
                      ))}
                    </div>

                    {/* ✅ Carousel Controls */}
                    {post.videos.length > 1 && (
                      <>
                        <button
                          className="carousel-control-prev"
                          type="button"
                          data-bs-target={`#carousel-${post.post_id}`}
                          data-bs-slide="prev"
                        >
                          <span
                            className="carousel-control-prev-icon"
                            aria-hidden="true"
                          ></span>
                          <span className="visually-hidden">Previous</span>
                        </button>
                        <button
                          className="carousel-control-next"
                          type="button"
                          data-bs-target={`#carousel-${post.post_id}`}
                          data-bs-slide="next"
                        >
                          <span
                            className="carousel-control-next-icon"
                            aria-hidden="true"
                          ></span>
                          <span className="visually-hidden">Next</span>
                        </button>
                      </>
                    )}
                  </div>
                )}

                {/* Description */}
                <div className="card-body">
                  <div
                    className="card-text"
                    dangerouslySetInnerHTML={{
                      __html: DOMPurify.sanitize(post.description),
                    }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
