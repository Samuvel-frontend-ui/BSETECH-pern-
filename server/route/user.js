const express = require("express");
const router = express.Router(); 
const authenticateToken = require("../middleware/auth"); 

const {
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
  followreqhandle
} = require("../controllers/user-controller");

router.post("/register",registered);

router.post("/login", logined);

router.post("/forgotpassword", forgot_password);

router.post("/reset-password", reset_password);

router.get("/users", authenticateToken, getusers);

router.post("/follow", authenticateToken, followbutton);

router.get("/following/:userId", authenticateToken, following);

router.get("/profile/:id", authenticateToken, profileget);

router.put("/profile/:id", authenticateToken, profileupdate);

router.get("/followers/list/:userId", authenticateToken, followerslist);

router.get("/following/list/:userId", authenticateToken, followinglist);

router.get("/followreq/:userId", authenticateToken, followrequest);

router.post("/followreq/handle/:requestId", authenticateToken, followreqhandle);

module.exports = router;
