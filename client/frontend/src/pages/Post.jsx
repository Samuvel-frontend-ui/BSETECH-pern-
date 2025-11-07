import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import ReactQuill from "react-quill";
import "react-quill/dist/quill.snow.css";
import axios from "axios";

export default function VideoInput() {
  const navigate = useNavigate();
  const [uploads, setUploads] = useState([]);
  const [description, setDescription] = useState("");
  const [fileList, setFileList] = useState([]);
  const [error, setError] = useState("");
  const [uploading, setUploading] = useState(false);

  // 📁 Handle File Selection
  const handleFileChange = (event) => {
    const files = Array.from(event.target.files);
    if (!files.length) return;

    const MAX_SIZE_MB = 500; // 500MB limit per file
    const invalidFiles = files.filter(
      (file) => file.type !== "video/mp4" || file.size > MAX_SIZE_MB * 1024 * 1024
    );

    if (invalidFiles.length > 0) {
      const invalidNames = invalidFiles.map((f) => f.name).join(", ");
      setError(
        `❌ Only MP4 files under ${MAX_SIZE_MB}MB are allowed. Invalid: ${invalidNames}`
      );
      return;
    }

    setError("");
    const newUploads = files.map((file) => ({
      id: URL.createObjectURL(file),
      name: file.name,
      progress: 0,
      uploaded: false,
    }));

    // Append instead of replace
    setUploads((prev) => [...prev, ...newUploads]);
    setFileList((prev) => [...prev, ...files]);

    // Simulated progress animation
    newUploads.forEach((upload) => {
      let currentProgress = 0;
      const interval = setInterval(() => {
        currentProgress += Math.floor(Math.random() * 10) + 1;
        if (currentProgress >= 100) {
          clearInterval(interval);
          currentProgress = 100;
          setUploads((prev) =>
            prev.map((item) =>
              item.id === upload.id
                ? { ...item, progress: 100, uploaded: true }
                : item
            )
          );
        } else {
          setUploads((prev) =>
            prev.map((item) =>
              item.id === upload.id
                ? { ...item, progress: currentProgress }
                : item
            )
          );
        }
      }, 200);
    });
  };

  // 🚀 Upload Post to Backend
  const uploadPost = async () => {
    setError("");

    if (!description.trim()) {
      setError("❌ Please enter a description before uploading.");
      return;
    }

    if (fileList.length === 0) {
      setError("❌ Please choose at least one MP4 video file.");
      return;
    }

    const formData = new FormData();
    fileList.forEach((file) => formData.append("videos", file));
    formData.append("description", description);

    try {
      setUploading(true);
      const token = localStorage.getItem("token"); 

      const response = await axios.post("http://localhost:5000/posts", formData, {
        headers: {
          "Content-Type": "multipart/form-data",
          Authorization: `Bearer ${token}`,
        },
        onUploadProgress: (progressEvent) => {
          const progress = Math.round(
            (progressEvent.loaded * 100) / progressEvent.total
          );
          setUploads((prev) =>
            prev.map((u) => ({ ...u, progress: progress }))
          );
        },
      });

      alert("✅ Post uploaded successfully!");
      console.log(response.data);

      navigate("/getpost");

      // Reset form
      setUploads([]);
      setFileList([]);
      setDescription("");
    } catch (error) {
      console.error("Error uploading post:", error);
      setError(
        error.response?.data?.message || "❌ Error uploading post. Please try again."
      );
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="container mt-4">
      {/* 🔙 Back Button */}
      <button className="btn btn-secondary mb-3" onClick={() => navigate("/home")}>
        ⬅ Back to Home
      </button>

      <div className="VideoInput card p-4 shadow">
        <h2 className="mb-3 text-center text-primary">Upload Video Post</h2>

        {/* 🧾 Description */}
        <div className="mb-4">
          <h4>Description</h4>
          <ReactQuill
            theme="snow"
            value={description}
            onChange={setDescription}
            placeholder="Type your video description here..."
            style={{ background: "#fff" }}
          />
        </div>

        {/* 📹 File Upload */}
        <div className="mb-3">
          <h4>Upload MP4 Videos (max 500 MB each)</h4>
          <input
            className="form-control"
            type="file"
            multiple
            accept=".mp4"
            onChange={handleFileChange}
          />
        </div>

        {/* ⚠️ Error */}
        {error && (
          <div className="alert alert-danger text-center" role="alert">
            {error}
          </div>
        )}

        {/* 📊 Preview & Progress */}
        <div className="row mt-3">
          {uploads.map((upload) => (
            <div key={upload.id} className="col-md-4 mb-3">
              <div className="card shadow-sm">
                <div className="card-body">
                  {upload.uploaded ? (
                    <>
                      <video
                        className="w-100 mb-2 rounded"
                        controls
                        src={upload.id}
                      />
                      <p className="text-success text-center mb-0">✅ Upload complete!</p>
                    </>
                  ) : (
                    <>
                      <p className="text-truncate">{upload.name}</p>
                      <div className="progress">
                        <div
                          className="progress-bar progress-bar-striped progress-bar-animated"
                          role="progressbar"
                          style={{ width: `${upload.progress}%` }}
                        >
                          {upload.progress}%
                        </div>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* 🚀 Submit */}
        <div className="mt-4 text-center">
          <button
            className="btn btn-success px-4"
            onClick={uploadPost}
            disabled={uploading}
          >
            {uploading ? "Uploading..." : "Upload Post 🚀"}
          </button>
        </div>
      </div>
    </div>
  );
}
