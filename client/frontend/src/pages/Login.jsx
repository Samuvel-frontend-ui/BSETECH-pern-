import React, { useState, useContext } from "react";
import { useNavigate, Link } from "react-router-dom";
import { AuthContext } from "../authcontext.jsx";
import axios from "axios";

function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [message, setMessage] = useState("");
  const navigate = useNavigate();
  const { login } = useContext(AuthContext);

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const response = await axios.post("http://localhost:5000/login", {
          email,
        password,

      });

      const data = response.data;

      if (!data.token) {
        setMessage(data.message || "Login failed");
        return;
      }

      login(data.token, data.user);
      setMessage("✅ Login successful!");
      navigate("/home");
    } catch (error) {
      console.error("Login error:", error);
      setMessage(error.response?.data?.message || "Server error, please try again.");
    }
  };

  return (
    <div className="container d-flex flex-column justify-content-center align-items-center vh-100">
      {/* Card */}
      <div className="card shadow-lg" style={{ maxWidth: "400px", width: "100%" }}>
        <div className="card-body p-4">
          <h2 className="card-title text-center mb-4">Welcome back 🤗</h2>

          <form onSubmit={handleSubmit}>
            {/* Email */}
            <div className="mb-3">
              <label className="form-label">Email</label>
              <input
                type="email"
                className="form-control"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>

            {/* Password */}
            <div className="mb-3">
              <label className="form-label">Password</label>
              <div className="input-group">
                <input
                  type={showPassword ? "text" : "password"}
                  className="form-control"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
                <button
                  type="button"
                  className="btn btn-outline-secondary"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? "Hide" : "Show"}
                </button>
              </div>
            </div>

            <div className="d-flex justify-content-end mt-3">
              <Link to="/forgotpassword" className="text-decoration-none small ">
                Forgot Password?
              </Link>
            </div>

            <button type="submit" className="btn btn-primary w-100">
              Login
            </button>
          </form>

          {message && (
            <div
              className={`mt-3 text-center ${
                message.includes("successful") ? "text-success" : "text-danger"
              }`}
            >
              {message}
            </div>
          )}
        </div>
      </div>

      {/* Register link outside card */}
      <p className="mt-3 text-center small">
        Don’t have an account?{" "}
        <Link to="/register" className="text-decoration-none fw-semibold text-primary">
          Register
        </Link>
      </p>
    </div>
  );
}

export default Login;
