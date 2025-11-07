import React, { useEffect, useState, useContext } from "react";
import { useNavigate, useParams } from "react-router-dom";
import axios from "axios";
import { AuthContext } from "../authcontext.jsx";
import PhoneInput from "react-phone-input-2";
import "react-phone-input-2/lib/style.css";

function Profile() {
  const { id } = useParams();
  const { user, token } = useContext(AuthContext);
  const navigate = useNavigate();

  const [profile, setProfile] = useState(null);
  const [loadingProfile, setLoadingProfile] = useState(true);
  const [editing, setEditing] = useState(false);
  const [followersCount, setFollowersCount] = useState(0);
  const [followingCount, setFollowingCount] = useState(0);

  const [formData, setFormData] = useState({
    username: "",
    email: "",
    accountType: "public",
    phoneNo: "",
    address: "",
  });

  const [pendingRequests, setPendingRequests] = useState([]);

  const [followersList, setFollowersList] = useState([]);
  const [followersPage, setFollowersPage] = useState(1);
  const [hasMoreFollowers, setHasMoreFollowers] = useState(true);
  const [loadingFollowers, setLoadingFollowers] = useState(false);

  const [followingList, setFollowingList] = useState([]);
  const [followingPage, setFollowingPage] = useState(1);
  const [hasMoreFollowing, setHasMoreFollowing] = useState(true);
  const [loadingFollowing, setLoadingFollowing] = useState(false);

  const itemsPerPage = 6;
  const [showFollowers, setShowFollowers] = useState(false);
  const [showFollowing, setShowFollowing] = useState(false);

  const isOwner = user && id && Number(user.id) === Number(id);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        if (!token || !id) return;
        const res = await axios.get(`http://localhost:5000/profile/${id}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const profileData = res.data;

        setFollowersCount(profileData.FollowersCount || 0);
        setFollowingCount(profileData.FollowingCount || 0);
        
        console.log("backend data: ", profileData);
        console.log("followerscount:", profileData.FollowersCount);
        console.log("followingcount:", profileData.FollowingCount);
        
        setProfile(profileData);

        setFormData({
          username: profileData.username || "",
          email: profileData.email || "",
          accountType: profileData.accountType || "public",
          phoneNo: profileData.phoneNo || "",
          address: profileData.address || "",
        });

        if (isOwner && profileData.accountType?.toLowerCase() === "private") {
          const requestsRes = await axios.get(
            `http://localhost:5000/followreq/${id}`,
            { headers: { Authorization: `Bearer ${token}` } }
          );
          setPendingRequests(requestsRes.data.pendingRequests || []);
        }
      } catch (err) {
        console.error("Error fetching profile:", err);
      } finally {
        setLoadingProfile(false);
      }
    };
    fetchProfile();
  }, [id, token, isOwner]);

  const fetchFollowers = async (page = 1) => {
    if (!id) return;
    setLoadingFollowers(true);
    try {
      const res = await axios.get(
        `http://localhost:5000/followers/list/${id}?page=${page}&limit=${itemsPerPage}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const data = res.data.followers || [];

      setFollowersList((prev) => (page === 1 ? data : [...prev, ...data]));
      setHasMoreFollowers(data.length === itemsPerPage);
      setFollowersPage(page);
    } catch (err) {
      console.error("Error fetching followers:", err);
    } finally {
      setLoadingFollowers(false);
    }
  };

  const fetchFollowing = async (page = 1) => {
    if (!id) return;
    setLoadingFollowing(true);
    try {
      const res = await axios.get(
        `http://localhost:5000/following/list/${id}?page=${page}&limit=${itemsPerPage}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const data = res.data.following || [];

      setFollowingList((prev) => (page === 1 ? data : [...prev, ...data]));
      setHasMoreFollowing(data.length === itemsPerPage);
      setFollowingPage(page);
    } catch (err) {
      console.error("Error fetching following:", err);
    } finally {
      setLoadingFollowing(false);
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleUpdate = async () => {
    try {
      const formattedPhone =
        formData.phoneNo && !formData.phoneNo.startsWith("+")
          ? `+${formData.phoneNo}`
          : formData.phoneNo;

      const res = await axios.put(
        `http://localhost:5000/profile/${id}`,
        {
          username: formData.username,
          email: formData.email,
          accountType: formData.accountType,
          phoneNo: formattedPhone,
          address: formData.address,
          loggedInUserId: user.id,
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      const updatedProfile = res.data;
      setProfile(updatedProfile);
      setFormData({
        username: updatedProfile.username || "",
        email: updatedProfile.email || "",
        accountType: updatedProfile.accountType || "public",
        phoneNo: updatedProfile.phoneNo || "",
        address: updatedProfile.address || "",
      });
      setEditing(false);
      alert("Profile updated!");
    } catch (err) {
      console.error("Failed to update profile:", err);
      alert("Failed to update profile");
    }
  };

  const handleRequestAction = async (requestId, action) => {
    try {
      await axios.post(
        `http://localhost:5000/followreq/handle/${requestId}`,
        { ownerId: user.id, action },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      setPendingRequests((prev) => prev.filter((r) => r.id !== requestId));

      if (action === "approve") {
        const approvedUser = pendingRequests.find((r) => r.id === requestId);
        if (approvedUser) {
          setFollowersList((prev) => [
            ...prev,
            {
              id: approvedUser.requesterId,
              username: approvedUser.username,
              profile_pic: approvedUser.profile_pic,
            },
          ]);
          setFollowersCount(prev => prev + 1);
        }      
      } 
    } catch (err) {
      console.error("Follow request action failed:", err);
      alert(`Failed to ${action === "approve" ? "approve" : "reject"} request`);
    }
  };

  const handleFollowAction = async (targetUserId, action) => {
    try {
      await axios.post(
        `http://localhost:5000/follow`,
        { 
          userId: user.id, 
          targetId: targetUserId,
          action: action,
          isRequest: false
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (action === "follow") {
        fetchFollowers(1);
        // Update following count if current user is following
        if (isOwner) {
          setFollowingCount(prev => prev + 1);
        }
      } else if (action === "unfollow") {
        setFollowingList((prev) => prev.filter((f) => f.id !== targetUserId));
        // Update following count
        if (isOwner) {
          setFollowingCount(prev => prev - 1);
        }
      }
      
      alert(`Successfully ${action === "follow" ? "followed" : "unfollowed"} user`);
    } catch (err) {
      console.error(`Failed to ${action}:`, err);
      alert(`Failed to ${action} user`);
    }
  };

   const handleFollowAction = async (targetUserId, action) => {
    try {
      await axios.post(
        `http://localhost:5000/follow`,
        { 
          userId: user.id, 
          targetId: targetUserId,
          action: action,
          isRequest: false
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (action === "follow") {
        fetchFollowers(1);
        // Update following count if current user is following
        if (isOwner) {
          setFollowingCount(prev => prev + 1);
        }
      } else if (action === "unfollow") {
        setFollowingList((prev) => prev.filter((f) => f.id !== targetUserId));
        // Update following count
        if (isOwner) {
          setFollowingCount(prev => prev - 1);
        }
      }
      
      alert(`Successfully ${action === "follow" ? "followed" : "unfollowed"} user`);
    } catch (err) {
      console.error(`Failed to ${action}:`, err);
      alert(`Failed to ${action} user`);
    }
  };
  
  if (loadingProfile) return <p className="text-center mt-4">Loading profile...</p>;
  if (!profile) return <p className="text-center mt-4">Profile not found</p>;

  return (
    <div className="container mt-4">
      <button className="btn btn-outline-secondary mb-4" onClick={() => navigate("/home")}>
        ⬅️ Back 
      </button>

      <div className="row">
        <div className="col-md-8">
          <div className="card shadow-sm p-4 mb-4">
            <div className="d-flex align-items-center mb-3">
              <img
                src={
                  profile.profile_pic
                    ? `http://localhost:5000/profile_pic/${profile.profile_pic}`
                    : "/default-profile.png"
                }
                alt={profile.username}
                className="rounded-circle border border-secondary me-3"
                style={{ width: "100px", height: "100px", objectFit: "cover" }}
              />
              <div className="flex-grow-1">
                <div className="d-flex align-items-center mb-2">
                  <h4 className="me-3 mb-0">{profile.username}</h4>
                  {isOwner && (
                    <button
                      className="btn btn-outline-primary btn-sm"
                      onClick={() => setEditing(true)}
                    >
                      Edit Profile
                    </button>
                  )}
                </div>
                
                <div className="d-flex gap-3">
                  <small
                    style={{ cursor: "pointer", color: "blue" }}
                    onClick={() => {
                      fetchFollowers(1);
                      setShowFollowers(true);
                      setShowFollowing(false);
                    }}
                  >
                    Followers {followersCount}
                  </small>
                  <small
                    style={{ cursor: "pointer", color: "blue" }}
                    onClick={() => {
                      fetchFollowing(1);
                      setShowFollowing(true);
                      setShowFollowers(false);
                    }}
                  >
                    Following {followingCount}
                  </small>
                </div>
              </div>
            </div>

            {editing ? (
              <div className="mt-3">
                <div className="mb-2">
                  <label className="form-label">Username</label>
                  <input
                    className="form-control"
                    name="username"
                    value={formData.username}
                    onChange={handleChange}
                  />
                </div>
                <div className="mb-2">
                  <label className="form-label">Email</label>
                  <input
                    className="form-control"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                  />
                </div>
                <div className="mb-2">
                  <label className="form-label">Phone Number</label>
                  <PhoneInput
                    country={"us"}
                    value={formData.phoneNo}
                    onChange={(phone) => setFormData((prev) => ({ ...prev, phoneNo: phone }))}
                    inputProps={{ name: "phoneNo", required: true, className: "form-control" }}
                    containerClass="w-100"
                  />
                </div>
                <div className="mb-2">
                  <label className="form-label">Address</label>
                  <input
                    className="form-control"
                    name="address"
                    value={formData.address}
                    onChange={handleChange}
                  />
                </div>
                <div className="mb-3">
                  <label className="form-label">Account Type</label>
                  <select
                    className="form-select"
                    name="accountType"
                    value={formData.accountType}
                    onChange={handleChange}
                  >
                    <option value="public">Public</option>
                    <option value="private">Private</option>
                  </select>
                </div>
                <div className="d-flex gap-2">
                  <button className="btn btn-success" onClick={handleUpdate}>
                    Save
                  </button>
                  <button className="btn btn-secondary" onClick={() => setEditing(false)}>
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <div className="mt-2">
                <p>
                  <strong>Email:</strong>{" "}
                  {isOwner || profile.accountType?.toLowerCase() === "public"
                    ? profile.email
                    : "Private"}
                </p>
                <p>
                  <strong>Phone Number:</strong>{" "}
                  {isOwner || profile.accountType?.toLowerCase() === "public"
                    ? profile.phoneNo || "-"
                    : "Private"}
                </p>
                <p>
                  <strong>Address:</strong>{" "}
                  {isOwner || profile.accountType?.toLowerCase() === "public"
                    ? profile.address || "-"
                    : "Private"}
                </p>
                <p>
                  <strong>Account Type:</strong> {profile.accountType}
                </p>
              </div>
            )}
          </div>

          {showFollowers && (
            <div className="card shadow-sm p-3 mt-3">
              <h5>Followers List ({followersList.length})</h5>
              {loadingFollowers ? (
                <p>Loading followers...</p>
              ) : followersList.length === 0 ? (
                <p>No followers found.</p>
              ) : (
                <>
                  {followersList.map((f) => (
                    <div key={f.id} className="d-flex align-items-center justify-content-between mb-2 p-2 border rounded">
                      <div className="d-flex align-items-center">
                        <img
                          src={
                            f.profile_pic
                              ? `http://localhost:5000/profile_pic/${f.profile_pic}`
                              : "/default-profile.png"
                          }
                          alt={f.username}
                          className="rounded-circle me-3"
                          style={{ width: "50px", height: "50px", objectFit: "cover" }}
                        />
                        <span>{f.username}</span>
                      </div>
                      {!isOwner && (
                        <button 
                          className="btn btn-success btn-sm" 
                          onClick={() => handleFollowAction(f.id, "follow")}
                        >
                          Follow
                        </button>
                      )}
                    </div>
                  ))}
                  {hasMoreFollowers && (
                    <button 
                      className="btn btn-primary btn-sm mt-2" 
                      onClick={() => fetchFollowers(followersPage + 1)}
                      disabled={loadingFollowers}
                    >
                      Load More
                    </button>
                  )}
                </>
              )}
            </div>
          )}

          {showFollowing && (
            <div className="card shadow-sm p-3 mt-3">
              <h5>Following List ({followingList.length})</h5>
              {loadingFollowing ? (
                <p>Loading following...</p>
              ) : followingList.length === 0 ? (
                <p>No following found.</p>
              ) : (
                <>
                  {followingList.map((f) => (
                    <div key={f.id} className="d-flex align-items-center justify-content-between mb-2 p-2 border rounded">
                      <div className="d-flex align-items-center">
                        <img
                          src={
                            f.profile_pic
                              ? `http://localhost:5000/profile_pic/${f.profile_pic}`
                              : "/default-profile.png"
                          }
                          alt={f.username}
                          className="rounded-circle me-3"
                          style={{ width: "50px", height: "50px", objectFit: "cover" }}
                        />
                        <span>{f.username}</span>
                      </div>
                      {isOwner && (
                        <button 
                          className="btn btn-danger btn-sm" 
                          onClick={() => handleFollowAction(f.id, "unfollow")}
                        >
                          Unfollow
                        </button>
                      )}
                    </div>
                  ))}
                  {hasMoreFollowing && (
                    <button 
                      className="btn btn-primary btn-sm mt-2" 
                      onClick={() => fetchFollowing(followingPage + 1)}
                      disabled={loadingFollowing}
                    >
                      Load More
                    </button>
                  )}
                </>
              )}
            </div>
          )}
        </div>

        {isOwner && profile.accountType?.toLowerCase() === "private" && (
          <div className="col-md-4">
            <div
              className="card shadow-sm p-3 mb-4"
              style={{ maxHeight: "600px", overflowY: "auto" }}
            >
              <h5>Pending Requests ({pendingRequests.length})</h5>
              {pendingRequests.length === 0 ? (
                <p className="mt-2">No pending requests.</p>
              ) : (
                pendingRequests.map((req) => (
                  <div
                    key={req.id}
                    className="d-flex justify-content-between align-items-center mb-2 p-2 border rounded"
                  >
                    <div className="d-flex align-items-center">
                      <img
                        src={
                          req.profile_pic
                            ? `http://localhost:5000/profile_pic/${req.profile_pic}`
                            : "/default-profile.png"
                        }
                        alt={req.username}
                        className="rounded-circle me-3"
                        style={{ width: "50px", height: "50px", objectFit: "cover" }}
                      />
                      <span>{req.username}</span>
                    </div>
                    <div className="d-flex gap-2">
                      <button
                        className="btn btn-success btn-sm"
                        onClick={() => handleRequestAction(req.id, "approve")}
                      >
                        Accept
                      </button>
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => handleRequestAction(req.id, "reject")}
                      >
                        Decline
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Profile;