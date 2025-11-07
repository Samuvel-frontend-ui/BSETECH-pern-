import Home from './pages/Home';
import Login from './pages/Login';
import Register from './pages/Register';
import Profile from './pages/Profile'
import Post from './pages/Post';
import VideoFeed from './pages/videofeed';
import { Routes, Route } from "react-router-dom";
import ForgotPassword from './pages/Forgotpassword';
import Resetpassword from './pages/Resetpassword';

function App() {
  return (
    <Routes>
      <Route path='/' element={<Register/>}/>
      <Route path='/register' element={<Register/>}/>
      <Route path='/login' element={<Login/>}/>
      <Route path="/forgotpassword" element={<ForgotPassword/>}/>
      <Route path="/reset-password" element={<Resetpassword/>}/>
      <Route path='/home' element={<Home/>}/>
      <Route path="/profile/:id" element={<Profile />} />
      <Route path="/post" element={<Post/>} />
      <Route path="/getpost" element={<VideoFeed/>} />
    </Routes>
  ) 
}

export default App;